#!/usr/bin/python3
"""
User Enumeration — OWASP Authentication testing.

Techniques:
  - Timing-based: measure response time difference between valid/invalid usernames
  - Response-based: detect different error messages or status codes
  - Default credentials: test common username/password pairs
  - Username wordlist: brute-force username existence

Usage:
  ../.venv/bin/python3 modules/user_enum.py -u https://target.com/login --user-field user --pass-field pass
  ../.venv/bin/python3 modules/user_enum.py -u https://target.com/login -w usernames.txt
  ../.venv/bin/python3 modules/user_enum.py -u https://target.com/login --default-creds
  ../.venv/bin/python3 modules/user_enum.py -u https://target.com/login -o results.json
"""
import argparse
import json
import statistics
import time
import urllib.parse

import requests
import urllib3

from core.colors import bold, end, good, bad, info, run
from core.auth_gate import preflight

urllib3.disable_warnings()

TIMEOUT = 15
UA = {"User-Agent": "Catch403/1.0"}

# ── default credential pairs ───────────────────────────────────────────────
DEFAULT_CREDS = [
    ("admin",     "admin"),
    ("admin",     "password"),
    ("admin",     "123456"),
    ("admin",     "admin123"),
    ("admin",     ""),
    ("root",      "root"),
    ("root",      "toor"),
    ("root",      "password"),
    ("test",      "test"),
    ("guest",     "guest"),
    ("demo",      "demo"),
    ("user",      "user"),
    ("manager",   "manager"),
    ("operator",  "operator"),
    ("superuser", "superuser"),
    ("sa",        "sa"),
    ("postgres",  "postgres"),
    ("oracle",    "oracle"),
    ("pi",        "raspberry"),
    ("ubnt",      "ubnt"),
]

# ── common usernames for enumeration ──────────────────────────────────────
BUILTIN_USERNAMES = [
    "admin", "administrator", "root", "test", "guest", "user", "demo",
    "info", "support", "webmaster", "noreply", "service", "dev", "api",
    "operator", "manager", "superuser", "sa", "postmaster", "hostmaster",
]

CANARY_USER = "xyzzy_nonexistent_user_12345"


def _post_login(url: str, user_field: str, pass_field: str,
                username: str, password: str, headers: dict) -> tuple[requests.Response, float]:
    data = {user_field: username, pass_field: password}
    t0 = time.perf_counter()
    r = requests.post(url, data=data, headers=headers,
                      timeout=TIMEOUT, verify=False, allow_redirects=False)
    elapsed = time.perf_counter() - t0
    return r, elapsed


def _timing_baseline(url: str, user_field: str, pass_field: str,
                     headers: dict, samples: int = 5) -> float:
    times = []
    for _ in range(samples):
        _, t = _post_login(url, user_field, pass_field,
                           CANARY_USER, "wrong_password_xyz", headers)
        times.append(t)
    return statistics.mean(times)


def _response_differs(r1: requests.Response, r2: requests.Response) -> bool:
    if r1.status_code != r2.status_code:
        return True
    # Significant body difference
    if abs(len(r1.text) - len(r2.text)) > 30:
        return True
    # Common enumeration phrases
    enum_phrases = [
        "user not found", "username not found", "invalid username",
        "no account", "does not exist", "incorrect username",
        "account not found",
    ]
    r1_lower = r1.text.lower()
    r2_lower = r2.text.lower()
    for phrase in enum_phrases:
        if (phrase in r1_lower) != (phrase in r2_lower):
            return True
    return False


def scan_timing(url: str, usernames: list[str], *,
                user_field: str = "username", pass_field: str = "password",
                cookie: str = "") -> list[dict]:
    headers = {**UA}
    if cookie:
        headers["Cookie"] = cookie

    findings = []
    baseline = _timing_baseline(url, user_field, pass_field, headers)
    threshold = baseline * 1.5 + 0.3   # 50% slower + 300ms minimum

    for username in usernames:
        try:
            _, t = _post_login(url, user_field, pass_field, username, "wrong_xyz", headers)
            if t > threshold:
                findings.append({
                    "name": f"User Enumeration (Timing) — '{username}'",
                    "severity": "medium",
                    "detail": (
                        f"Response {t:.2f}s vs baseline {baseline:.2f}s "
                        f"(threshold {threshold:.2f}s) — user may exist"
                    ),
                    "username": username,
                })
        except requests.RequestException:
            continue

    return findings


def scan_response(url: str, usernames: list[str], *,
                  user_field: str = "username", pass_field: str = "password",
                  cookie: str = "") -> list[dict]:
    headers = {**UA}
    if cookie:
        headers["Cookie"] = cookie

    findings = []
    try:
        baseline_r, _ = _post_login(url, user_field, pass_field,
                                    CANARY_USER, "wrong_xyz", headers)
    except requests.RequestException:
        return findings

    for username in usernames:
        try:
            r, _ = _post_login(url, user_field, pass_field, username, "wrong_xyz", headers)
            if _response_differs(r, baseline_r):
                findings.append({
                    "name": f"User Enumeration (Response) — '{username}'",
                    "severity": "medium",
                    "detail": (
                        f"Status {baseline_r.status_code}→{r.status_code}, "
                        f"Body length {len(baseline_r.text)}→{len(r.text)}"
                    ),
                    "username": username,
                })
        except requests.RequestException:
            continue

    return findings


def scan_default_creds(url: str, *,
                       user_field: str = "username", pass_field: str = "password",
                       cookie: str = "") -> list[dict]:
    headers = {**UA}
    if cookie:
        headers["Cookie"] = cookie

    findings = []
    try:
        baseline_r, _ = _post_login(url, user_field, pass_field,
                                    CANARY_USER, "wrong_xyz", headers)
        base_status = baseline_r.status_code
        base_len = len(baseline_r.text)
    except requests.RequestException:
        return findings

    for username, password in DEFAULT_CREDS:
        try:
            r, _ = _post_login(url, user_field, pass_field, username, password, headers)
            # Success indicators: different status, redirect, or body shrinks (no error msg)
            success = (
                r.status_code in (200, 302) and base_status not in (200, 302)
            ) or (
                r.status_code == base_status
                and abs(len(r.text) - base_len) > 100
            )
            if success:
                findings.append({
                    "name": "Default Credentials Accepted",
                    "severity": "critical",
                    "detail": f"Login succeeded with {username!r}:{password!r} (status {r.status_code})",
                    "username": username,
                    "password": password,
                })
        except requests.RequestException:
            continue

    return findings


def scan(url: str, usernames: list[str] | None = None, *,
         user_field: str = "username", pass_field: str = "password",
         cookie: str = "", check_defaults: bool = True,
         check_timing: bool = True, check_response: bool = True) -> list[dict]:
    words = usernames or BUILTIN_USERNAMES
    findings = []

    if check_defaults:
        findings += scan_default_creds(url, user_field=user_field,
                                       pass_field=pass_field, cookie=cookie)
    if check_response:
        findings += scan_response(url, words, user_field=user_field,
                                  pass_field=pass_field, cookie=cookie)
    if check_timing:
        findings += scan_timing(url, words, user_field=user_field,
                                pass_field=pass_field, cookie=cookie)

    if not findings:
        findings.append({
            "name": "No User Enumeration Detected",
            "severity": "info",
            "detail": "Responses appear consistent across valid and invalid usernames",
        })
    return findings


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    from modules.wordlists import WL, add_wordlist_arg
    parser = argparse.ArgumentParser(description="Catch403 User Enumeration")
    parser.add_argument("-u", dest="url", required=True)
    parser.add_argument("--user-field", default="username")
    parser.add_argument("--pass-field", default="password")
    add_wordlist_arg(parser, "usernames", help_suffix="Accepts registry name or file path.")
    parser.add_argument("--default-creds", action="store_true",
                        help="Test default credential pairs only")
    parser.add_argument("--no-timing", action="store_true")
    parser.add_argument("--no-response", action="store_true")
    parser.add_argument("--cookie", default="")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    preflight('user_enum', args.url, active=True)

    usernames = (WL.resolve(args.wordlist, "usernames") if args.wordlist
                 else WL.usernames()) or BUILTIN_USERNAMES

    parsed = urllib.parse.urlparse(args.url)
    print(f"{run} User enumeration: {bold}{parsed.netloc}{parsed.path}{end}")
    print(f"{info} Testing {len(usernames)} usernames + {len(DEFAULT_CREDS)} default cred pairs\n")

    results = scan(
        args.url, usernames,
        user_field=args.user_field, pass_field=args.pass_field,
        cookie=args.cookie,
        check_defaults=True,
        check_timing=not args.no_timing,
        check_response=not args.no_response,
    )

    for f in results:
        sev = f.get("severity", "info")
        prefix = (bad if sev == "critical"
                  else f"{bold}[{sev.upper()}]{end}" if sev in ("high", "medium")
                  else info)
        print(f"{prefix} {bold}{f['name']}{end}")
        print(f"        {f['detail']}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n{good} Saved to {args.output}")


if __name__ == "__main__":
    main()
