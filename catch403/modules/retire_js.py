#!/usr/bin/python3
"""
Retire.js — detect vulnerable JavaScript libraries in web pages.

Fetches a URL, finds all <script> src references, downloads each JS file
and checks version strings against a built-in vulnerability database covering
the most common libraries (jQuery, Angular, React, Bootstrap, Lodash, etc.).

Usage:
  ../.venv/bin/python3 modules/retire_js.py -u https://target.com
  ../.venv/bin/python3 modules/retire_js.py -u https://target.com/app.js  (single file)
"""
import argparse
import re
import urllib.parse

import requests
import urllib3

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab

urllib3.disable_warnings()

# ── vulnerability database ─────────────────────────────────────────────────
# Format: library → list of {below, severity, cve, summary}
# Versions parsed via semver-lite comparison (major.minor.patch ints).

VULNDB = {
    "jquery": {
        "detect": [r"jquery[.-]v?(\d+\.\d+[\.\d]*)(?:\.min)?\.js",
                   r"/\*!? jQuery v(\d+\.\d+[\.\d]*)"],
        "vulns": [
            {"below": "1.9.0",  "severity": "medium", "cve": "CVE-2012-6708", "summary": "Selector interpreted as HTML"},
            {"below": "1.12.0", "severity": "medium", "cve": "CVE-2015-9251", "summary": "3rd party CORS request may execute"},
            {"below": "3.0.0",  "severity": "medium", "cve": "CVE-2015-9251", "summary": "3rd party CORS request may execute"},
            {"below": "3.4.0",  "severity": "medium", "cve": "CVE-2019-11358", "summary": "Prototype pollution via Object.assign"},
            {"below": "3.5.0",  "severity": "medium", "cve": "CVE-2020-11022", "summary": "XSS via jQuery.htmlPrefilter"},
            {"below": "3.5.0",  "severity": "medium", "cve": "CVE-2020-11023", "summary": "XSS via passing HTML containing <option> elements"},
        ],
    },
    "angular": {
        "detect": [r"angular[.-]v?(\d+\.\d+[\.\d]*)(?:\.min)?\.js",
                   r"@angular/core.*?(\d+\.\d+[\.\d]*)",
                   r"AngularJS v(\d+\.\d+[\.\d]*)"],
        "vulns": [
            {"below": "1.6.0",  "severity": "high",   "cve": "CVE-2016-9873",  "summary": "XSS via SVG animations"},
            {"below": "1.6.5",  "severity": "medium", "cve": "CVE-2017-1000466","summary": "Open redirect"},
            {"below": "1.8.0",  "severity": "medium", "cve": "CVE-2020-7676",  "summary": "XSS via ng-template"},
        ],
    },
    "bootstrap": {
        "detect": [r"bootstrap[.-]v?(\d+\.\d+[\.\d]*)(?:\.min)?\.(?:js|css)",
                   r"/\*!? Bootstrap v(\d+\.\d+[\.\d]*)"],
        "vulns": [
            {"below": "3.4.0",  "severity": "medium", "cve": "CVE-2018-14040", "summary": "XSS via data-target attribute"},
            {"below": "3.4.1",  "severity": "medium", "cve": "CVE-2019-8331",  "summary": "XSS in tooltip/popover"},
            {"below": "4.3.1",  "severity": "medium", "cve": "CVE-2019-8331",  "summary": "XSS in tooltip/popover"},
        ],
    },
    "lodash": {
        "detect": [r"lodash[.-]v?(\d+\.\d+[\.\d]*)(?:\.min)?\.js",
                   r"(?:lodash|_) v?(\d+\.\d+[\.\d]*)"],
        "vulns": [
            {"below": "4.17.11","severity": "high",   "cve": "CVE-2018-16487","summary": "Prototype pollution"},
            {"below": "4.17.19","severity": "high",   "cve": "CVE-2020-8203", "summary": "Prototype pollution via zipObjectDeep"},
            {"below": "4.17.21","severity": "high",   "cve": "CVE-2021-23337","summary": "Command injection via template"},
        ],
    },
    "moment": {
        "detect": [r"moment[.-]v?(\d+\.\d+[\.\d]*)(?:\.min)?\.js",
                   r"moment\.js.*?(\d+\.\d+[\.\d]*)"],
        "vulns": [
            {"below": "2.29.2", "severity": "high",   "cve": "CVE-2022-24785","summary": "Path traversal in locale"},
            {"below": "2.29.4", "severity": "high",   "cve": "CVE-2022-31129","summary": "ReDoS in date parsing"},
        ],
    },
    "handlebars": {
        "detect": [r"handlebars[.-]v?(\d+\.\d+[\.\d]*)(?:\.min)?\.js"],
        "vulns": [
            {"below": "4.7.7",  "severity": "high",   "cve": "CVE-2021-23369","summary": "Prototype pollution via template"},
            {"below": "4.7.7",  "severity": "high",   "cve": "CVE-2021-23383","summary": "Prototype pollution via square-bracket notation"},
        ],
    },
    "underscore": {
        "detect": [r"underscore[.-]v?(\d+\.\d+[\.\d]*)(?:\.min)?\.js"],
        "vulns": [
            {"below": "1.13.0", "severity": "high",   "cve": "CVE-2021-23358","summary": "Prototype pollution via template function"},
        ],
    },
    "vue": {
        "detect": [r"vue[.-]v?(\d+\.\d+[\.\d]*)(?:\.min)?\.js",
                   r"Vue\.version\s*=\s*['\"](\d+\.\d+[\.\d]*)"],
        "vulns": [
            {"below": "2.6.0",  "severity": "medium", "cve": "CVE-2018-10990","summary": "XSS via SSR content"},
        ],
    },
}


def _ver_tuple(v: str) -> tuple:
    try:
        return tuple(int(x) for x in re.split(r"[.\-]", v)[:3])
    except Exception:
        return (0, 0, 0)


def _is_below(version: str, threshold: str) -> bool:
    return _ver_tuple(version) < _ver_tuple(threshold)


def _detect_version(lib: str, content: str) -> str | None:
    for pattern in VULNDB[lib]["detect"]:
        m = re.search(pattern, content, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _check_lib(lib: str, version: str) -> list[dict]:
    findings = []
    for v in VULNDB[lib]["vulns"]:
        if _is_below(version, v["below"]):
            findings.append({**v, "lib": lib, "version": version})
    return findings


def scan_content(content: str, source: str = "") -> list[dict]:
    findings = []
    for lib in VULNDB:
        version = _detect_version(lib, content)
        if version:
            vulns = _check_lib(lib, version)
            if vulns:
                findings.extend(vulns)
            else:
                findings.append({"lib": lib, "version": version, "severity": "info",
                                 "cve": "", "summary": "No known vulnerabilities",
                                 "below": "", "source": source})
                continue
            for f in vulns:
                f["source"] = source
    return findings


def scan_url(url: str) -> list[dict]:
    ua = {"User-Agent": "Mozilla/5.0"}
    findings = []
    try:
        r = requests.get(url, headers=ua, timeout=15, verify=False)
    except Exception as e:
        print(f"{bad} {red}Error: {e}{end}"); return []

    content_type = r.headers.get("Content-Type","")
    if "javascript" in content_type or url.endswith(".js"):
        print(f"{run} Scanning JS file: {bold}{url}{end}")
        return scan_content(r.text, source=url)

    # HTML page — find all script srcs
    script_srcs = re.findall(r'<script[^>]+src=[\'"]([^\'"]+)[\'"]', r.text, re.I)
    inline      = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.I | re.S)
    base        = urllib.parse.urljoin(url, "/")

    print(f"{run} Found {len(script_srcs)} external scripts + {len(inline)} inline blocks on {bold}{url}{end}")

    # Check inline scripts first
    for block in inline:
        findings.extend(scan_content(block, source=f"{url} (inline)"))

    # Fetch each external script
    for src in script_srcs:
        full = urllib.parse.urljoin(url, src)
        try:
            js = requests.get(full, headers=ua, timeout=10, verify=False)
            findings.extend(scan_content(js.text, source=full))
        except Exception:
            pass

    return findings


def print_findings(findings: list[dict]) -> None:
    sev_col = {"high": red, "medium": yellow, "low": green, "info": ""}
    vulns   = [f for f in findings if f.get("cve")]
    clean   = [f for f in findings if not f.get("cve")]

    if not findings:
        print(f"{good} No JavaScript libraries detected."); return

    if vulns:
        print(f"\n{bold}{underline}Vulnerable libraries ({len(vulns)} issues){end}\n")
        seen = set()
        for f in vulns:
            key = (f["lib"], f["version"], f["cve"])
            if key in seen: continue
            seen.add(key)
            col = sev_col.get(f["severity"],"")
            print(f"  {col}{bold}[{f['severity'].upper()}]{end}  {bold}{f['lib']}{end} v{f['version']}")
            print(f"  {tab}CVE     : {f['cve']}")
            print(f"  {tab}Summary : {f['summary']}")
            print(f"  {tab}Fix at  : >= {f['below']}")
            print(f"  {tab}Source  : {f.get('source','')}\n")
    else:
        print(f"{good} No vulnerable versions found for detected libraries.")

    if clean:
        print(f"{info} Clean libraries detected: " + ", ".join(f"{f['lib']} v{f['version']}" for f in clean))


def main():
    parser = argparse.ArgumentParser(description="Detect vulnerable JavaScript libraries (like Burp Retire.js)")
    parser.add_argument("-u", dest="url", required=True, help="Target URL or JS file URL")
    args = parser.parse_args()
    findings = scan_url(args.url)
    print_findings(findings)


if __name__ == "__main__":
    main()
