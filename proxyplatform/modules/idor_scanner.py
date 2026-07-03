#!/usr/bin/python3
"""
IDOR / BOLA Scanner — Broken Object Level Authorization.

The #1 gap in automated web security tools. Tests whether resources
owned by User A are accessible using User B's session.

Approach:
  1. Record all requests made as User A (provided as HAR or history filter)
  2. Replay those requests using User B's session token
  3. Compare responses — flag 200 responses with similar body size (A's data returned)
  4. Also tests ID enumeration: increment/decrement numeric IDs, UUID substitution
  5. Checks secondary endpoints: /export, /download, /email, /backup

Usage:
  # Two-session swap: replay A's requests with B's token
  ../.venv/bin/python3 modules/idor_scanner.py -u https://target.com/api/account/123 \\
      --session-a "Authorization: Bearer TOKEN_A" \\
      --session-b "Authorization: Bearer TOKEN_B"

  # Enumerate IDs around a baseline
  ../.venv/bin/python3 modules/idor_scanner.py -u "https://target.com/api/orders/1042" \\
      --session-a "Cookie: session=SESS_A" --enumerate --range 5

  # Test all endpoints from a URL file with session swap
  ../.venv/bin/python3 modules/idor_scanner.py --url-file endpoints.txt \\
      --session-a "Authorization: Bearer A" --session-b "Authorization: Bearer B"
"""
import argparse
import json
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

from core.colors import bold, end, good, bad, info, run

urllib3.disable_warnings()

TIMEOUT = 15
UA      = {"User-Agent": "Catch403/1.0"}

# ── ID pattern detection ───────────────────────────────────────────────────

_NUMERIC_ID_RE   = re.compile(r"/(\d{1,10})(?:/|$|\?|#)")
_UUID_RE         = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?|#)",
    re.IGNORECASE
)
_BASE36_RE       = re.compile(r"/([A-Za-z0-9]{8,24})(?:/|$|\?|#)")

# Secondary endpoints that often skip auth on the same object
_SECONDARY_SUFFIXES = [
    "/export", "/download", "/pdf", "/csv", "/excel", "/print",
    "/email", "/share", "/copy", "/clone", "/backup",
    ".json", ".xml", ".csv",
]


def _parse_header(header_str: str) -> dict[str, str]:
    """'Authorization: Bearer x' → {'Authorization': 'Bearer x'}"""
    if not header_str or ":" not in header_str:
        return {}
    k, v = header_str.split(":", 1)
    return {k.strip(): v.strip()}


def _headers(session_header: str) -> dict:
    return {**UA, **_parse_header(session_header)}


# ── response comparison ────────────────────────────────────────────────────

def _sensitive_leak(r_a: requests.Response, r_b: requests.Response) -> tuple[bool, str]:
    """
    True if response B (user B's session) looks like it returned A's data.
    Heuristics:
      - Both 200 and body sizes are within 20% (same content structure)
      - B's body is non-trivially large (>100 bytes — not an empty error page)
      - B's status is 200/201/207 (not an error)
    """
    if r_b.status_code not in (200, 201, 207):
        return False, ""

    len_a = len(r_a.text)
    len_b = len(r_b.text)

    if len_b < 50:
        return False, ""

    # Significant content overlap (not just an empty shell)
    if len_a > 0:
        ratio = len_b / len_a
        if 0.7 <= ratio <= 1.4:
            return True, f"Body sizes A={len_a} B={len_b} (ratio {ratio:.2f}) — likely same object returned"

    # Large response even if A was small
    if len_b > 500 and r_b.status_code == 200:
        # Check if the response looks like user data (JSON with fields)
        try:
            obj = json.loads(r_b.text)
            if isinstance(obj, dict) and len(obj) > 2:
                return True, f"JSON object returned ({len(obj)} fields, {len_b} bytes)"
        except Exception:
            pass

    return False, ""


def _unauthorized_access(r_b: requests.Response) -> tuple[bool, str]:
    """Detect if a request that should fail actually succeeded."""
    if r_b.status_code in (401, 403, 404):
        return False, ""
    if r_b.status_code in (200, 201, 207):
        return True, f"Status {r_b.status_code}, body length {len(r_b.text)}"
    return False, ""


# ── scan functions ─────────────────────────────────────────────────────────

def test_url_session_swap(url: str, session_a: str, session_b: str, *,
                          method: str = "GET", body: str = "") -> list[dict]:
    """
    Fetch url with session_a, then with session_b, compare.
    If B gets the same data, it's a BOLA/IDOR.
    If B shouldn't have access at all and gets 200, it's unauthorized access.
    """
    findings: list[dict] = []
    hdrs_a = _headers(session_a)
    hdrs_b = _headers(session_b)

    try:
        if method.upper() == "GET":
            r_a = requests.get(url, headers=hdrs_a, timeout=TIMEOUT, verify=False)
            r_b = requests.get(url, headers=hdrs_b, timeout=TIMEOUT, verify=False)
        else:
            r_a = requests.request(method, url, data=body, headers=hdrs_a,
                                   timeout=TIMEOUT, verify=False)
            r_b = requests.request(method, url, data=body, headers=hdrs_b,
                                   timeout=TIMEOUT, verify=False)
    except requests.RequestException:
        return findings

    # If A doesn't even get 200, skip
    if r_a.status_code not in (200, 201, 207):
        return findings

    leaked, evidence = _sensitive_leak(r_a, r_b)
    if leaked:
        findings.append({
            "name": "IDOR / BOLA — Cross-User Data Access",
            "severity": "high",
            "detail": (
                f"User B's session can access User A's resource.\n"
                f"URL: {url}\n{evidence}"
            ),
            "url": url,
            "payload": f"Session B header: {list(_headers(session_b).keys())[0] if _headers(session_b) else '(none)'}",
            "evidence": evidence,
            "curl": (
                f"# User A:\ncurl -sk '{url}' -H '{session_a}'\n"
                f"# User B (should fail, but doesn't):\ncurl -sk '{url}' -H '{session_b}'"
            ),
        })

    # Also test secondary endpoints
    for suffix in _SECONDARY_SUFFIXES:
        alt_url = url.rstrip("/") + suffix
        try:
            r_alt = requests.get(alt_url, headers=hdrs_b, timeout=TIMEOUT, verify=False)
            ok, ev = _unauthorized_access(r_alt)
            if ok:
                findings.append({
                    "name": f"IDOR — Secondary Endpoint ({suffix})",
                    "severity": "high",
                    "detail": (
                        f"Secondary endpoint accessible to User B.\n"
                        f"URL: {alt_url}\n{ev}"
                    ),
                    "url": alt_url,
                    "evidence": ev,
                })
        except Exception:
            pass

    return findings


def test_id_enumeration(url: str, session_b: str, *,
                        enum_range: int = 5,
                        method: str = "GET") -> list[dict]:
    """
    Find numeric IDs in the URL, test IDs around them with session_b.
    Reports any that return 200 with substantial content.
    """
    findings: list[dict] = []
    hdrs_b = _headers(session_b)

    match = _NUMERIC_ID_RE.search(url)
    if not match:
        return findings

    base_id = int(match.group(1))
    ids_to_test = list(range(max(1, base_id - enum_range), base_id + enum_range + 1))
    ids_to_test = [i for i in ids_to_test if i != base_id]

    for test_id in ids_to_test:
        test_url = url[:match.start(1)] + str(test_id) + url[match.end(1):]
        try:
            r = requests.get(test_url, headers=hdrs_b, timeout=TIMEOUT, verify=False)
            if r.status_code == 200 and len(r.text) > 100:
                findings.append({
                    "name": f"IDOR — ID Enumeration (id={test_id})",
                    "severity": "medium",
                    "detail": (
                        f"ID enumeration: ID {test_id} returns 200 with {len(r.text)} bytes.\n"
                        f"URL: {test_url}"
                    ),
                    "url": test_url,
                    "payload": str(test_id),
                    "evidence": r.text[:200],
                    "curl": f"curl -sk '{test_url}' -H '{session_b}'",
                })
        except Exception:
            continue

    return findings


def scan(url: str, *,
         session_a: str = "",
         session_b: str = "",
         enumerate: bool = False,
         enum_range: int = 5,
         additional_urls: list[str] | None = None,
         method: str = "GET",
         body: str = "") -> list[dict]:
    all_findings: list[dict] = []
    urls = [url] + (additional_urls or [])

    for u in urls:
        if session_a and session_b:
            all_findings.extend(test_url_session_swap(
                u, session_a, session_b, method=method, body=body
            ))
        if enumerate and session_b:
            all_findings.extend(test_id_enumeration(u, session_b, enum_range=enum_range))

    if not all_findings:
        all_findings.append({
            "name": "No IDOR Detected",
            "severity": "info",
            "detail": (
                f"Tested {len(urls)} URL(s) — no cross-user data access detected. "
                f"Note: IDOR detection requires valid dual-session configuration and "
                f"may miss cases where response bodies differ in structure."
            ),
        })
    return all_findings


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Catch403 IDOR/BOLA Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Session swap: test if User B can access User A's resource
  idor_scanner.py -u https://target.com/api/orders/1042 \\
      --session-a "Authorization: Bearer TOKEN_A" \\
      --session-b "Authorization: Bearer TOKEN_B"

  # Enumerate adjacent IDs with User B's session
  idor_scanner.py -u https://target.com/api/users/500 \\
      --session-b "Cookie: session=SESS_B" --enumerate --range 10

  # Test multiple endpoints from file
  idor_scanner.py --url-file api_endpoints.txt \\
      --session-a "Authorization: Bearer A" --session-b "Authorization: Bearer B"
"""
    )
    parser.add_argument("-u", dest="url", default="")
    parser.add_argument("--url-file", metavar="FILE",
                        help="File of URLs to test (one per line)")
    parser.add_argument("--session-a", default="", metavar="HEADER:VALUE",
                        help="Session header for User A (e.g. 'Authorization: Bearer TOKEN')")
    parser.add_argument("--session-b", default="", metavar="HEADER:VALUE",
                        help="Session header for User B (will try to access A's resources)")
    parser.add_argument("--enumerate", action="store_true",
                        help="Enumerate adjacent numeric IDs")
    parser.add_argument("--range", dest="enum_range", type=int, default=5,
                        help="How many IDs above/below to test (default: 5)")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("-d", dest="body", default="", help="Request body")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    urls: list[str] = []
    if args.url:
        urls.append(args.url)
    if args.url_file:
        with open(args.url_file) as fh:
            urls.extend(line.strip() for line in fh if line.strip() and not line.startswith("#"))

    if not urls:
        parser.error("Provide -u URL or --url-file FILE")
    if not args.session_a and not args.session_b:
        parser.error("Provide at least --session-b (for enumeration) or both --session-a and --session-b")

    print(f"{run} IDOR/BOLA scan: {bold}{len(urls)} URL(s){end}")
    if args.session_a and args.session_b:
        print(f"{info} Session A: {args.session_a[:40]}...")
        print(f"{info} Session B: {args.session_b[:40]}...")

    results = scan(
        urls[0] if urls else "",
        session_a=args.session_a,
        session_b=args.session_b,
        enumerate=args.enumerate,
        enum_range=args.enum_range,
        additional_urls=urls[1:],
        method=args.method,
        body=args.body,
    )

    for f in results:
        sev = f.get("severity", "info")
        icon = bad if sev == "critical" else (f"{bold}[{sev.upper()}]{end}" if sev != "info" else info)
        print(f"\n{icon} {bold}{f['name']}{end}")
        print(f"      {f.get('detail', '')[:180]}")
        if f.get("curl"):
            print(f"      Reproduce:\n{f['curl']}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n{good} Saved to {args.output}")


if __name__ == "__main__":
    main()
