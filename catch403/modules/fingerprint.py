#!/usr/bin/python3
"""
Fingerprint — web application and technology identification.

Covers the OWASP Information Gathering category:
  - Server banner and header analysis
  - CMS/framework detection (WordPress, Drupal, Joomla, Laravel, Django, Rails, etc.)
  - Web server detection (Apache, Nginx, IIS, Caddy, Tomcat, etc.)
  - JavaScript library detection (React, Angular, Vue, jQuery, Bootstrap, etc.)
  - robots.txt, sitemap.xml, .DS_Store, .git/HEAD recon files
  - Technology stack from HTML meta tags, generator tags, error pages

Usage:
  ../.venv/bin/python3 modules/fingerprint.py -u https://target.com
  ../.venv/bin/python3 modules/fingerprint.py -u https://target.com --deep
  ../.venv/bin/python3 modules/fingerprint.py -u https://target.com -o report.json
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

TIMEOUT = 10
UA = {"User-Agent": "Catch403/1.0"}

# ── signature databases ────────────────────────────────────────────────────

SERVER_SIGNATURES = {
    r"Apache(?:/(\S+))?":           "Apache",
    r"nginx(?:/(\S+))?":            "Nginx",
    r"Microsoft-IIS(?:/(\S+))?":    "IIS",
    r"LiteSpeed":                   "LiteSpeed",
    r"Caddy":                       "Caddy",
    r"Apache-Coyote":               "Tomcat",
    r"Jetty(?:/(\S+))?":            "Jetty",
    r"Kestrel":                     "ASP.NET Kestrel",
    r"Gunicorn(?:/(\S+))?":         "Gunicorn",
    r"Werkzeug(?:/(\S+))?":         "Werkzeug/Flask",
    r"Python(?:/(\S+))?":           "Python HTTP server",
    r"Node\.js":                    "Node.js",
    r"OpenResty(?:/(\S+))?":        "OpenResty/Nginx+Lua",
}

CMS_SIGNATURES = {
    # WordPress
    r"/wp-content/":                        "WordPress",
    r"/wp-includes/":                       "WordPress",
    r'name="generator" content="WordPress': "WordPress",
    r"wp-json":                             "WordPress (REST API)",
    # Drupal
    r"/sites/default/files/":              "Drupal",
    r'name="generator" content="Drupal':   "Drupal",
    r"Drupal\.settings":                   "Drupal (JS)",
    # Joomla
    r"/components/com_":                   "Joomla",
    r'name="generator" content="Joomla':   "Joomla",
    # Magento
    r"Mage\.Cookies":                      "Magento",
    r"/skin/frontend/":                    "Magento",
    # Shopify
    r"cdn\.shopify\.com":                  "Shopify",
    r"Shopify\.theme":                     "Shopify",
    # Ghost
    r'content="Ghost':                     "Ghost CMS",
    # Wix
    r"static\.wixstatic\.com":             "Wix",
    # Squarespace
    r"squarespace\.com":                   "Squarespace",
    # TYPO3
    r"typo3/":                             "TYPO3",
}

FRAMEWORK_SIGNATURES = {
    # Laravel
    r"laravel_session":                    "Laravel",
    r'<meta name="csrf-token"':            "Laravel (or Django/Rails)",
    # Django
    r"csrfmiddlewaretoken":                "Django",
    r"django":                             "Django",
    # Rails
    r"authenticity_token":                 "Ruby on Rails",
    r"_rails_session":                     "Ruby on Rails",
    # Spring
    r"org\.springframework":               "Spring Framework",
    r"SPRING_SECURITY":                    "Spring Security",
    # ASP.NET
    r"__VIEWSTATE":                        "ASP.NET WebForms",
    r"__RequestVerificationToken":         "ASP.NET MVC",
    r"ASP\.NET_SessionId":                 "ASP.NET",
    # Symfony
    r"symfony":                            "Symfony",
    # Next.js
    r"__NEXT_DATA__":                      "Next.js",
    r"/_next/":                            "Next.js",
    # Nuxt
    r"__NUXT__":                           "Nuxt.js",
    # Vue
    r"data-v-[a-f0-9]+":                  "Vue.js",
    # React
    r"__reactFiber":                       "React",
    r"react-root":                         "React",
    # Angular
    r"ng-version":                         "Angular",
    r"_nghost-":                           "Angular",
    # Express
    r"X-Powered-By: Express":             "Express.js",
}

JS_SIGNATURES = {
    r"jquery(?:\.min)?\.js":              "jQuery",
    r"bootstrap(?:\.min)?\.js":           "Bootstrap",
    r"angular(?:\.min)?\.js":             "AngularJS",
    r"react(?:\.min)?\.js":              "React",
    r"vue(?:\.min)?\.js":                "Vue.js",
    r"lodash(?:\.min)?\.js":             "Lodash",
    r"moment(?:\.min)?\.js":             "Moment.js",
    r"axios(?:\.min)?\.js":              "Axios",
    r"gsap(?:\.min)?\.js":               "GSAP",
    r"chart\.js":                        "Chart.js",
    r"d3(?:\.min)?\.js":                 "D3.js",
    r"three(?:\.min)?\.js":              "Three.js",
    r"socket\.io":                       "Socket.IO",
    r"underscore(?:\.min)?\.js":         "Underscore.js",
}

RECON_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.git/HEAD",
    "/.env",
    "/.DS_Store",
    "/crossdomain.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/.htaccess",
    "/web.config",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/elmah.axd",
    "/.svn/entries",
    "/.hg/requires",
    "/WEB-INF/web.xml",
    "/wp-config.php.bak",
    "/config.php.bak",
]


def _match_signatures(text: str, sigs: dict) -> list[str]:
    found = []
    for pattern, label in sigs.items():
        if re.search(pattern, text, re.IGNORECASE):
            if label not in found:
                found.append(label)
    return found


def scan(url: str, *, deep: bool = False, cookie: str = "") -> list[dict]:
    findings: list[dict] = []
    parsed = urllib.parse.urlparse(url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    headers = {**UA}
    if cookie:
        headers["Cookie"] = cookie

    # ── fetch main page ────────────────────────────────────────────────────
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT,
                         verify=False, allow_redirects=True)
    except requests.RequestException as e:
        return [{"name": "Connection Failed", "severity": "info", "detail": str(e)}]

    body = r.text
    resp_headers = dict(r.headers)

    # ── server banner ──────────────────────────────────────────────────────
    server_hdr = resp_headers.get("Server", "") + resp_headers.get("X-Powered-By", "")
    for pattern, label in SERVER_SIGNATURES.items():
        m = re.search(pattern, server_hdr, re.IGNORECASE)
        if m:
            version = m.group(1) if m.lastindex else ""
            findings.append({
                "name": f"Web Server: {label}" + (f" {version}" if version else ""),
                "severity": "info",
                "detail": f"Server header: {resp_headers.get('Server', 'n/a')}",
                "category": "fingerprint",
            })
            break

    # Version disclosure in Server header
    if re.search(r"[/\s]\d+\.\d+", server_hdr):
        findings.append({
            "name": "Server Version Disclosure",
            "severity": "low",
            "detail": f"Version leaked in Server/X-Powered-By: {server_hdr.strip()}",
            "category": "fingerprint",
        })

    # X-Powered-By
    xpb = resp_headers.get("X-Powered-By", "")
    if xpb:
        findings.append({
            "name": f"X-Powered-By: {xpb}",
            "severity": "low",
            "detail": "Technology stack disclosed in response header",
            "category": "fingerprint",
        })

    # ── CMS detection ──────────────────────────────────────────────────────
    cms_hits = _match_signatures(body, CMS_SIGNATURES)
    for label in cms_hits:
        findings.append({
            "name": f"CMS Detected: {label}",
            "severity": "info",
            "detail": f"Signature found in page HTML/JS",
            "category": "fingerprint",
        })

    # ── framework detection ────────────────────────────────────────────────
    fw_hits = _match_signatures(body + str(resp_headers), FRAMEWORK_SIGNATURES)
    for label in fw_hits:
        findings.append({
            "name": f"Framework Detected: {label}",
            "severity": "info",
            "detail": "Signature found in response body or headers",
            "category": "fingerprint",
        })

    # ── JS library detection ───────────────────────────────────────────────
    js_hits = _match_signatures(body, JS_SIGNATURES)
    for label in js_hits:
        findings.append({
            "name": f"JS Library: {label}",
            "severity": "info",
            "detail": "Script reference found in HTML",
            "category": "fingerprint",
        })

    # ── generator meta tag ─────────────────────────────────────────────────
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                  body, re.IGNORECASE)
    if not m:
        m = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
                      body, re.IGNORECASE)
    if m:
        findings.append({
            "name": f"Generator Tag: {m.group(1)}",
            "severity": "low",
            "detail": "Meta generator tag discloses CMS/framework version",
            "category": "fingerprint",
        })

    # ── recon files ────────────────────────────────────────────────────────
    paths = RECON_PATHS if deep else RECON_PATHS[:10]
    for path in paths:
        try:
            rr = requests.get(root + path, headers=headers, timeout=TIMEOUT,
                              verify=False, allow_redirects=False)
            if rr.status_code == 200:
                sev = "high" if path in ("/.env", "/.git/HEAD", "/phpinfo.php",
                                          "/WEB-INF/web.xml") else "medium"
                findings.append({
                    "name": f"Recon File Accessible: {path}",
                    "severity": sev,
                    "detail": f"HTTP 200 — {len(rr.text)} bytes",
                    "url": root + path,
                    "category": "recon",
                })
        except requests.RequestException:
            continue

    if not findings:
        findings.append({
            "name": "No Technology Fingerprints Found",
            "severity": "info",
            "detail": "No known CMS, framework, or server signatures detected",
        })

    return findings


# ── CLI ────────────────────────────────────────────────────────────────────

_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def main():
    parser = argparse.ArgumentParser(description="Catch403 Fingerprint")
    parser.add_argument("-u", dest="url", required=True)
    parser.add_argument("--deep", action="store_true",
                        help="Check all recon paths (default: first 10)")
    parser.add_argument("--cookie", default="")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    preflight('fingerprint', args.url, active=False)

    parsed = urllib.parse.urlparse(args.url)
    print(f"{run} Fingerprinting: {bold}{parsed.netloc}{parsed.path}{end}\n")

    results = scan(args.url, deep=args.deep, cookie=args.cookie)
    results.sort(key=lambda f: _SEV.get(f.get("severity", "info"), 4))

    prev_cat = None
    for f in results:
        cat = f.get("category", "")
        if cat and cat != prev_cat:
            print(f"\n  {bold}{cat.upper()}{end}")
            prev_cat = cat
        sev = f.get("severity", "info")
        prefix = (bad if sev == "critical"
                  else f"{bold}[{sev.upper()}]{end}" if sev in ("high", "medium")
                  else info)
        print(f"{prefix} {bold}{f['name']}{end}")
        if f.get("detail"):
            print(f"        {f['detail']}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n{good} Saved to {args.output}")


if __name__ == "__main__":
    main()
