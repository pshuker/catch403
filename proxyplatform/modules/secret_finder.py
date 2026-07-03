#!/usr/bin/python3
"""
Secret Finder — scans HTTP responses for hardcoded secrets, API keys, tokens.

Inspired by the Burp Secret Finder extension. Checks URLs or pasted text
against 40+ regex patterns covering AWS, GCP, GitHub, Stripe, Twilio, JWT,
private keys, connection strings, and more.

Usage:
  ../.venv/bin/python3 modules/secret_finder.py -u https://target.com
  ../.venv/bin/python3 modules/secret_finder.py -f response.txt
  ../.venv/bin/python3 modules/secret_finder.py -u https://target.com/app.js
"""
import argparse
import re
import sys

import requests

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, que, tab

# ── pattern library ────────────────────────────────────────────────────────
PATTERNS = [
    # Cloud providers
    ("AWS Access Key",       "high",   r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    ("AWS Secret Key",       "high",   r"(?i)aws.{0,20}['\"][0-9a-zA-Z\/+]{40}['\"]"),
    ("AWS MWS Key",          "medium", r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ("GCP API Key",          "high",   r"AIza[0-9A-Za-z\-_]{35}"),
    ("GCP Service Account",  "high",   r'"type":\s*"service_account"'),
    ("Azure Storage Key",    "high",   r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"),
    # Tokens & API keys
    ("GitHub Token",         "high",   r"ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}"),
    ("GitHub OAuth",         "high",   r"[0-9a-f]{40}"),
    ("GitLab Token",         "high",   r"glpat-[A-Za-z0-9\-_]{20}"),
    ("Stripe Secret Key",    "high",   r"sk_live_[0-9a-zA-Z]{24}"),
    ("Stripe Publishable",   "low",    r"pk_live_[0-9a-zA-Z]{24}"),
    ("Stripe Test Key",      "info",   r"sk_test_[0-9a-zA-Z]{24}"),
    ("Twilio API Key",       "high",   r"SK[0-9a-fA-F]{32}"),
    ("Twilio Account SID",   "medium", r"AC[a-zA-Z0-9]{32}"),
    ("Twilio Auth Token",    "high",   r"(?i)twilio.{0,20}['\"][0-9a-zA-Z]{32}['\"]"),
    ("SendGrid API Key",     "high",   r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    ("Mailgun API Key",      "high",   r"key-[0-9a-zA-Z]{32}"),
    ("Slack Token",          "high",   r"xox[baprs]-[0-9A-Za-z]{10,48}"),
    ("Slack Webhook",        "high",   r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("Facebook Token",       "high",   r"EAACEdEose0cBA[0-9A-Za-z]+"),
    ("Twitter Bearer",       "high",   r"AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+"),
    ("Google OAuth",         "high",   r"ya29\.[0-9A-Za-z\-_]+"),
    ("Heroku API Key",       "high",   r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    ("PagerDuty Key",        "high",   r"(?i)pagerduty.{0,20}['\"][a-z0-9]{20}['\"]"),
    ("Shopify Token",        "high",   r"shpss_[a-fA-F0-9]{32}|shpat_[a-fA-F0-9]{32}"),
    # Secrets & passwords
    ("Generic Secret",       "medium", r"(?i)(?:secret|passwd|password|api_key|apikey|auth_token|access_token)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    ("Generic API Key",      "medium", r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][^'\"]{16,}['\"]"),
    ("Bearer Token",         "medium", r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}"),
    ("Basic Auth",           "medium", r"(?i)authorization:\s*basic\s+[a-zA-Z0-9+/=]{8,}"),
    # Private keys
    ("RSA Private Key",      "high",   r"-----BEGIN RSA PRIVATE KEY-----"),
    ("EC Private Key",       "high",   r"-----BEGIN EC PRIVATE KEY-----"),
    ("PGP Private Key",      "high",   r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    ("Private Key (generic)","high",   r"-----BEGIN (?:DSA |OPENSSH )?PRIVATE KEY-----"),
    ("Certificate",          "low",    r"-----BEGIN CERTIFICATE-----"),
    # Connection strings
    ("DB Connection String", "high",   r"(?i)(?:mysql|postgres|postgresql|mongodb|redis|mssql)://[^\s\"']+:[^\s\"']+@[^\s\"']+"),
    ("JDBC URL",             "high",   r"jdbc:[a-z:]+://[^\s\"']+"),
    # JWTs
    ("JWT",                  "info",   r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    # Internal IPs
    ("Internal IP",          "low",    r"(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}"),
    # Cloud metadata
    ("GCP Metadata URL",     "medium", r"metadata\.google\.internal"),
    ("AWS Metadata URL",     "medium", r"169\.254\.169\.254"),
]

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEVERITY_COLOR = {"high": red, "medium": yellow, "low": green, "info": ""}

# ── scanner ────────────────────────────────────────────────────────────────

def scan_text(text: str, source: str = "") -> list[dict]:
    findings = []
    for name, severity, pattern in PATTERNS:
        for match in re.finditer(pattern, text):
            findings.append({
                "name":     name,
                "severity": severity,
                "match":    match.group()[:120],
                "offset":   match.start(),
                "source":   source,
            })
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return findings


def scan_url(url: str, headers: dict | None = None) -> list[dict]:
    h = headers or {"User-Agent": "Mozilla/5.0"}
    try:
        r = requests.get(url, headers=h, timeout=15, verify=False)
        print(f"{run} Scanning {bold}{url}{end}  [{r.status_code}, {len(r.text)} bytes]")
        return scan_text(r.text, source=url)
    except Exception as e:
        print(f"{bad} {red}Error fetching {url}: {e}{end}")
        return []


def print_findings(findings: list[dict]) -> None:
    if not findings:
        print(f"{good} No secrets found.")
        return
    print(f"\n{bold}{underline}Findings ({len(findings)}){end}\n")
    for f in findings:
        col = SEVERITY_COLOR.get(f["severity"], "")
        sev = f"[{f['severity'].upper()}]"
        print(f"  {col}{bold}{sev:<10}{end} {bold}{f['name']}{end}")
        print(f"  {tab}Match : {f['match']!r}")
        if f["source"]:
            print(f"  {tab}Source: {f['source']}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Scan responses for hardcoded secrets and API keys")
    parser.add_argument("-u",   dest="url",  help="URL to fetch and scan")
    parser.add_argument("-f",   dest="file", help="File to scan")
    parser.add_argument("-s",   dest="severity", default="info",
                        choices=["high","medium","low","info"], help="Minimum severity to report")
    args = parser.parse_args()

    min_sev = SEVERITY_ORDER[args.severity]

    if args.file:
        with open(args.file, errors="replace") as f:
            text = f.read()
        findings = scan_text(text, source=args.file)
    elif args.url:
        findings = scan_url(args.url)
    else:
        parser.error("Provide -u URL or -f file.")

    findings = [f for f in findings if SEVERITY_ORDER.get(f["severity"], 99) <= min_sev]
    print_findings(findings)


if __name__ == "__main__":
    import urllib3; urllib3.disable_warnings()
    main()
