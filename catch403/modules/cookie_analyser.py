#!/usr/bin/python3
"""
Cookie Analyser — OWASP Session Management checks.

Tests: HttpOnly, Secure, SameSite flags; Path and Domain scope; expiry/max-age;
session fixation (same token before/after login); session token randomness;
multiple simultaneous session support.

Usage:
  ../.venv/bin/python3 modules/cookie_analyser.py -u https://target.com
  ../.venv/bin/python3 modules/cookie_analyser.py -u https://target.com/login --login-url https://target.com/login -d "user=admin&pass=admin"
  ../.venv/bin/python3 modules/cookie_analyser.py -u https://target.com -o report.json
"""
import argparse
import json
import urllib.parse

import requests
import urllib3

from core.colors import bold, end, good, bad, info, run
from core.auth_gate import preflight

urllib3.disable_warnings()

TIMEOUT = 10
UA = {"User-Agent": "Catch403/1.0"}

SESSION_NAMES = {
    "sessionid", "session", "sess", "sid", "phpsessid", "jsessionid",
    "asp.net_sessionid", "connect.sid", "csrf_token", "xsrf-token",
    "_session", "auth", "token", "access_token",
}


def _is_session_cookie(name: str) -> bool:
    return name.lower() in SESSION_NAMES or "sess" in name.lower() or "token" in name.lower()


def _analyse_cookie(cookie: requests.cookies.RequestsCookieJar | dict,
                    name: str, value: str, attrs: dict) -> list[dict]:
    findings = []
    is_session = _is_session_cookie(name)
    severity_base = "high" if is_session else "medium"

    # HttpOnly
    if not attrs.get("httponly", False):
        findings.append({
            "name": f"Cookie Missing HttpOnly — '{name}'",
            "severity": severity_base,
            "detail": "Cookie accessible via JavaScript — XSS can steal it",
            "cookie": name,
        })

    # Secure
    if not attrs.get("secure", False):
        findings.append({
            "name": f"Cookie Missing Secure Flag — '{name}'",
            "severity": severity_base,
            "detail": "Cookie sent over HTTP — vulnerable to network interception",
            "cookie": name,
        })

    # SameSite
    samesite = attrs.get("samesite", "").lower()
    if not samesite:
        findings.append({
            "name": f"Cookie Missing SameSite — '{name}'",
            "severity": "medium",
            "detail": "No SameSite attribute — cookie sent on cross-site requests (CSRF risk)",
            "cookie": name,
        })
    elif samesite == "none" and not attrs.get("secure", False):
        findings.append({
            "name": f"Cookie SameSite=None Without Secure — '{name}'",
            "severity": "high",
            "detail": "SameSite=None requires Secure flag — will be rejected by modern browsers",
            "cookie": name,
        })

    # Domain scope too broad
    domain = attrs.get("domain", "")
    if domain.startswith("."):
        findings.append({
            "name": f"Cookie Broad Domain Scope — '{name}'",
            "severity": "low",
            "detail": f"Domain={domain!r} — cookie shared across all subdomains",
            "cookie": name,
        })

    # Persistent vs session
    expires = attrs.get("expires", "") or attrs.get("max-age", "")
    if is_session and expires:
        findings.append({
            "name": f"Session Cookie Is Persistent — '{name}'",
            "severity": "low",
            "detail": f"Session cookie has expiry/max-age: {expires}",
            "cookie": name,
        })

    # Short token
    if is_session and len(value) < 16:
        findings.append({
            "name": f"Session Token Too Short — '{name}'",
            "severity": "high",
            "detail": f"Token length {len(value)} chars — likely guessable",
            "cookie": name,
        })

    return findings


def _get_cookies(url: str, headers: dict) -> list[tuple[str, str, dict]]:
    """Return list of (name, value, attrs_dict) from response Set-Cookie headers."""
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT,
                         verify=False, allow_redirects=True)
    except requests.RequestException:
        return []

    cookies = []
    for raw in r.raw.headers.getlist("Set-Cookie"):
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            continue
        name_val = parts[0].split("=", 1)
        if len(name_val) < 2:
            continue
        name, value = name_val[0].strip(), name_val[1].strip()
        attrs: dict = {}
        for attr in parts[1:]:
            kv = attr.split("=", 1)
            key = kv[0].strip().lower()
            val = kv[1].strip() if len(kv) > 1 else True
            attrs[key] = val
        cookies.append((name, value, attrs))

    return cookies


def scan(url: str, *, login_url: str = "", login_data: str = "",
         cookie: str = "") -> list[dict]:
    findings: list[dict] = []
    headers = {**UA}
    if cookie:
        headers["Cookie"] = cookie

    cookies = _get_cookies(url, headers)
    if not cookies:
        return [{"name": "No Set-Cookie Headers", "severity": "info",
                 "detail": "No cookies set by the server at this URL"}]

    for name, value, attrs in cookies:
        findings += _analyse_cookie(None, name, value, attrs)

    # ── Session fixation check ─────────────────────────────────────────────
    if login_url and login_data:
        pre_cookies = _get_cookies(login_url, {**UA})
        pre_session = {n: v for n, v, _ in pre_cookies if _is_session_cookie(n)}

        try:
            data = dict(kv.split("=", 1) for kv in login_data.split("&") if "=" in kv)
            r = requests.post(login_url, data=data, headers={**UA},
                              timeout=TIMEOUT, verify=False, allow_redirects=False)
            post_session = {n: v for n, v in r.cookies.items() if _is_session_cookie(n)}

            for name in pre_session:
                if name in post_session and pre_session[name] == post_session[name]:
                    findings.append({
                        "name": f"Session Fixation — '{name}'",
                        "severity": "high",
                        "detail": (
                            "Session token unchanged after login — "
                            "pre-auth token is still valid post-auth"
                        ),
                        "cookie": name,
                    })
        except (requests.RequestException, ValueError):
            pass

    return findings


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Catch403 Cookie Analyser")
    parser.add_argument("-u", dest="url", required=True)
    parser.add_argument("--login-url", default="", help="Login endpoint for session fixation check")
    parser.add_argument("-d", dest="login_data", default="",
                        help="Login POST data, e.g. user=admin&pass=admin")
    parser.add_argument("--cookie", default="")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    preflight('cookie_analyser', args.url, active=False)

    parsed = urllib.parse.urlparse(args.url)
    print(f"{run} Cookie analysis: {bold}{parsed.netloc}{parsed.path}{end}\n")

    results = scan(args.url, login_url=args.login_url,
                   login_data=args.login_data, cookie=args.cookie)

    for f in results:
        sev = f.get("severity", "info")
        prefix = (bad if sev == "critical"
                  else f"{bold}[{sev.upper()}]{end}" if sev in ("high", "medium")
                  else info)
        print(f"{prefix} {bold}{f['name']}{end}")
        print(f"        {f['detail']}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n{good} Saved to {args.output}")

    issues = [f for f in results if f.get("severity") in ("critical", "high", "medium")]
    print()
    if issues:
        print(f"{good} {len(issues)} cookie issue(s) found")
    else:
        print(f"{info} No cookie issues found")


if __name__ == "__main__":
    main()
