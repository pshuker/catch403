#!/usr/bin/python3
"""
Wapiti Scanner — DAST web application scanner for Catch403.

Wapiti crawls the target web application and injects payloads to detect:
XSS, SQLi, Command Injection, Path Traversal, SSRF, XXE, Open Redirect,
CRLF Injection, CSRF, File Inclusion, Htaccess Bypass, and more.

Output is JSON — parsed back into the standard finding format.

Usage:
  ../.venv/bin/python3 modules/wapiti_scanner.py -u https://target.com
  ../.venv/bin/python3 modules/wapiti_scanner.py -u https://target.com --depth 3 --threads 8
  ../.venv/bin/python3 modules/wapiti_scanner.py -u https://target.com --module xss,sql,blindsql
  ../.venv/bin/python3 modules/wapiti_scanner.py -u https://target.com --cookie "session=abc"
  ../.venv/bin/python3 modules/wapiti_scanner.py -u https://target.com --proxy http://127.0.0.1:8080
  ../.venv/bin/python3 modules/wapiti_scanner.py -u https://target.com -o report.json
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse

from core.colors import bold, end, good, bad, info, run

_HERE = os.path.dirname(os.path.abspath(__file__))


def _wapiti_bin() -> tuple[list[str], str]:
    venv_bin = os.path.abspath(os.path.join(_HERE, "..", "..", ".venv", "bin", "wapiti"))
    if os.path.isfile(venv_bin):
        return ([venv_bin], "pip wapiti3 (venv)")
    found = shutil.which("wapiti")
    if found:
        return ([found], "system wapiti")
    raise RuntimeError(
        "wapiti not found.\n"
        "  .venv/bin/pip install wapiti3"
    )


# ── severity mapping ───────────────────────────────────────────────────────

_WAPITI_SEVERITY = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

# Wapiti module names → human labels
_MODULE_LABELS = {
    "sql":          "SQL Injection",
    "blindsql":     "Blind SQL Injection",
    "xss":          "Cross-Site Scripting (XSS)",
    "exec":         "Command Execution",
    "file":         "Path Traversal / File Inclusion",
    "redirect":     "Open Redirect",
    "ssrf":         "Server-Side Request Forgery",
    "xxe":          "XML External Entity (XXE)",
    "csrf":         "CSRF",
    "crlf":         "CRLF Injection",
    "htaccess":     "Htaccess Bypass",
    "methods":      "Dangerous HTTP Methods",
    "shellshock":   "Shellshock",
    "spring4shell": "Spring4Shell",
    "log4shell":    "Log4Shell",
    "permanentxss": "Stored XSS",
    "drupal":       "Drupal",
    "wordpress":    "WordPress",
    "cms":          "CMS Detection",
    "network":      "Network Device",
    "ldapi":        "LDAP Injection",
    "nikto":        "Nikto checks",
    "wapp":         "Technology fingerprint",
}


def _parse_report(report: dict) -> list[dict]:
    findings = []

    for module_name, vulns in report.get("vulnerabilities", {}).items():
        label = _MODULE_LABELS.get(module_name.lower(), module_name)
        for v in vulns:
            sev_int = v.get("level", 1)
            sev = _WAPITI_SEVERITY.get(sev_int, "medium")
            findings.append({
                "name": label,
                "severity": sev,
                "detail": v.get("info", ""),
                "url": v.get("path", ""),
                "parameter": v.get("parameter", ""),
                "method": v.get("method", ""),
                "http_request": v.get("http_request", ""),
                "curl": v.get("curl_command", ""),
            })

    for module_name, anomalies in report.get("anomalies", {}).items():
        label = _MODULE_LABELS.get(module_name.lower(), module_name)
        for a in anomalies:
            findings.append({
                "name": f"Anomaly — {label}",
                "severity": "low",
                "detail": a.get("info", ""),
                "url": a.get("path", ""),
            })

    for key, val in report.get("infos", {}).items():
        if val:
            findings.append({
                "name": f"Info — {key}",
                "severity": "info",
                "detail": str(val),
            })

    return findings


# ── main scanner ───────────────────────────────────────────────────────────

def scan(
    url: str,
    *,
    depth: int = 2,
    threads: int = 6,
    module: str = "",
    cookie: str = "",
    proxy: str = "",
    timeout: int = 6,
    scope: str = "folder",
    extra_args: list[str] | None = None,
) -> list[dict]:
    """
    Crawl and scan url with wapiti, return findings as list[dict].

    scope: page | folder | domain | url | punk
    """
    cmd_prefix, _source = _wapiti_bin()
    tmp = tempfile.mkdtemp(prefix="catch403_wapiti_")
    report_file = os.path.join(tmp, "report.json")

    cmd = [
        *cmd_prefix,
        "--url", url,
        "--format", "json",
        "--output", report_file,
        "--depth", str(depth),
        "--max-links-per-page", "50",
        "--scope", scope,
        "--jobs", str(threads),
        "--timeout", str(timeout),
        "--color", "0",
        "--no-bugreport",
    ]
    if module:
        cmd += ["--module", module]
    if cookie:
        cmd += ["--cookie", cookie]
    if proxy:
        cmd += ["--proxy", proxy]
    if extra_args:
        cmd += extra_args

    findings: list[dict] = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if os.path.isfile(report_file):
            with open(report_file) as fh:
                report = json.load(fh)
            findings = _parse_report(report)
        else:
            combined = proc.stdout + "\n" + proc.stderr
            findings = [{
                "name": "Wapiti error",
                "severity": "info",
                "detail": combined[-4000:],
            }]
        combined = proc.stdout + "\n" + proc.stderr
        findings.append({
            "name": "_wapiti_raw",
            "severity": "meta",
            "detail": combined[-8000:],
        })
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return findings


# ── CLI ────────────────────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "meta": 5}


def main():
    parser = argparse.ArgumentParser(description="Catch403 Wapiti DAST Scanner")
    parser.add_argument("-u", dest="url", required=True)
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--threads", type=int, default=6, help="Parallel jobs (default: 6)")
    parser.add_argument("--module", default="",
                        help="Comma-separated wapiti modules, e.g. xss,sql,exec")
    parser.add_argument("--cookie", default="")
    parser.add_argument("--proxy", default="")
    parser.add_argument("--timeout", type=int, default=6, help="Per-request timeout (default: 6)")
    parser.add_argument("--scope", default="folder",
                        choices=["page", "folder", "domain", "url", "punk"])
    parser.add_argument("--raw", action="store_true")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    parsed = urllib.parse.urlparse(args.url)
    print(f"{run} Starting wapiti against {bold}{parsed.netloc}{parsed.path}{end}")
    print(f"{info} Depth {args.depth}  Threads {args.threads}  Scope {args.scope}")

    try:
        _, label = _wapiti_bin()
        print(f"{info} Using: {label}")
    except RuntimeError as e:
        print(f"{bad} {e}")
        sys.exit(1)

    print(f"{info} Crawling and scanning — this may take a few minutes...")
    print()

    results = scan(
        args.url, depth=args.depth, threads=args.threads,
        module=args.module, cookie=args.cookie, proxy=args.proxy,
        timeout=args.timeout, scope=args.scope,
    )

    raw = next((f for f in results if f.get("name") == "_wapiti_raw"), None)
    visible = [f for f in results if f.get("severity") != "meta"]
    visible.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 4))

    for f in visible:
        sev = f.get("severity", "info")
        if sev == "critical":
            prefix = bad
        elif sev in ("high", "medium"):
            prefix = f"{bold}[{sev.upper()}]{end}"
        else:
            prefix = info
        print(f"{prefix} {bold}{f['name']}{end}")
        if f.get("detail"):
            print(f"        {f['detail']}")
        if f.get("url"):
            print(f"        URL: {f['url']}")
        if f.get("curl"):
            print(f"        Curl: {f['curl']}")

    if args.raw and raw:
        print(f"\n{info} Raw wapiti output:\n{raw['detail']}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(visible, fh, indent=2)
        print(f"\n{good} Saved to {args.output}")

    critical_high = [f for f in visible if f.get("severity") in ("critical", "high")]
    print()
    if critical_high:
        print(f"{good} {len(critical_high)} critical/high finding(s)")
    else:
        print(f"{info} Scan complete — {len(visible)} finding(s) total")


if __name__ == "__main__":
    main()
