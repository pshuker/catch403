#!/usr/bin/python3
"""
Autorize — broken access control / authorization tester.

Replays a list of authenticated requests using a lower-privileged (or no)
session token and compares responses. Flags endpoints where the server
returns the same content to a lower-priv user.

Usage:
  # Replay a single request with a different cookie:
  ../.venv/bin/python3 modules/autorize.py -r request.txt --cookie "session=lowpriv_token"

  # Replay all requests in a file (one Burp request per block, separated by ---):
  ../.venv/bin/python3 modules/autorize.py -f requests.txt --cookie "session=lowpriv_token"
  ../.venv/bin/python3 modules/autorize.py -f requests.txt --no-auth
"""
import argparse
import difflib

import requests
import urllib3

import Burpee.burpee as burp
from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab

urllib3.disable_warnings()

STATUS_COLOR = {2: green, 3: "\033[94m", 4: yellow, 5: red}

SIMILARITY_THRESHOLD = 0.90   # 90% similar body → likely same content → BYPASSED


def _do_request(method: str, url: str, headers: dict, body: str,
                extra_cookies: dict | None = None,
                drop_auth: bool = False) -> requests.Response:
    h = dict(headers)
    if drop_auth:
        for k in list(h.keys()):
            if k.lower() in ("authorization", "cookie", "x-auth-token", "x-api-key"):
                del h[k]
    if extra_cookies:
        existing = h.get("Cookie", "")
        new_cookies = "; ".join(f"{k}={v}" for k, v in extra_cookies.items())
        h["Cookie"] = f"{existing}; {new_cookies}".strip("; ")
    data = body.strip() or None
    return requests.request(method, url, headers=h, data=data,
                            timeout=15, verify=False, allow_redirects=False)


def _similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a[:5000], b[:5000]).ratio()


def _parse_cookie_str(s: str) -> dict:
    result = {}
    for part in s.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            result[k.strip()] = v.strip()
    return result


def test_request(request_file: str, lowpriv_cookies: dict,
                 drop_auth: bool = False) -> dict:
    import urllib.parse
    headers, body = burp.parse_request(request_file)
    method, resource = burp.get_method_and_resource(request_file)
    host   = headers.get("Host", "")
    scheme = "https"
    url    = f"{scheme}://{host}{resource}"

    # Original (high-priv) request
    try:
        orig = _do_request(method, url, headers, body)
    except Exception as e:
        return {"url": url, "error": str(e)}

    # Low-priv / no-auth request
    try:
        low = _do_request(method, url, headers, body,
                          extra_cookies=lowpriv_cookies if not drop_auth else None,
                          drop_auth=drop_auth)
    except Exception as e:
        return {"url": url, "orig_status": orig.status_code, "error": str(e)}

    sim     = _similarity(orig.text, low.text)
    bypassed = (sim >= SIMILARITY_THRESHOLD and low.status_code < 400)
    return {
        "url":         url,
        "method":      method,
        "orig_status": orig.status_code,
        "low_status":  low.status_code,
        "similarity":  round(sim * 100, 1),
        "bypassed":    bypassed,
        "orig_len":    len(orig.content),
        "low_len":     len(low.content),
    }


def print_result(r: dict) -> None:
    if "error" in r:
        print(f"  {bad} {r.get('url','?')}  — {red}{r['error']}{end}")
        return
    sim   = r["similarity"]
    byp   = r["bypassed"]
    col   = green if byp else (yellow if sim > 50 else red)
    label = f"{green}BYPASSED{end}" if byp else f"{yellow}SIMILAR({sim}%){end}" if sim > 50 else f"{red}BLOCKED{end}"
    print(f"  {col}{'✓' if byp else '✗'}{end}  {r['method']:<6} {r['url']}")
    print(f"     {tab}Orig: {r['orig_status']} ({r['orig_len']} B)  →  Low: {r['low_status']} ({r['low_len']} B)  Similarity: {sim}%  {label}")


def main():
    parser = argparse.ArgumentParser(description="Replay requests with lower-privilege auth to detect broken access control")
    parser.add_argument("-r", dest="request",  help="Single Burp request file")
    parser.add_argument("-f", dest="reqfile",  help="File of request files (one path per line)")
    parser.add_argument("--cookie",  dest="cookie", default="",
                        help="Low-priv session cookie string (e.g. 'session=abc123; role=user')")
    parser.add_argument("--no-auth", dest="no_auth", action="store_true",
                        help="Remove all auth headers (test unauthenticated access)")
    args = parser.parse_args()

    cookies = _parse_cookie_str(args.cookie) if args.cookie else {}
    files   = []
    if args.request:
        files.append(args.request)
    if args.reqfile:
        with open(args.reqfile) as f:
            files += [line.strip() for line in f if line.strip()]
    if not files:
        parser.error("Provide -r request_file or -f file_list.")

    print(f"{run} {bold}Autorize{end} — testing {len(files)} request(s) with {'no-auth' if args.no_auth else 'low-priv cookie'}\n")
    bypassed = 0
    for req_file in files:
        result = test_request(req_file, cookies, drop_auth=args.no_auth)
        print_result(result)
        if result.get("bypassed"):
            bypassed += 1

    print(f"\n{bold}Summary:{end} {bypassed}/{len(files)} endpoint(s) appear bypassed.")


if __name__ == "__main__":
    main()
