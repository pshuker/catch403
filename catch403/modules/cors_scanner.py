#!/usr/bin/python3
"""
CORS Scanner — tests for Cross-Origin Resource Sharing misconfigurations.

Tests: wildcard origin, null origin, credential reflection, arbitrary origin
reflection, subdomain trust, protocol downgrade (http vs https), pre-flight
bypass, and exposed sensitive headers.

Usage:
  ../.venv/bin/python3 modules/cors_scanner.py -u https://target.com/api/data
  ../.venv/bin/python3 modules/cors_scanner.py -u https://target.com --cookie "session=abc"
  ../.venv/bin/python3 modules/cors_scanner.py -u https://target.com -o report.json
"""
import argparse
import json
import urllib.parse

import requests
import urllib3

from core.colors import bold, end, good, bad, info, run

urllib3.disable_warnings()

TIMEOUT = 10
UA = {"User-Agent": "Catch403/1.0"}

SENSITIVE_RESP_HEADERS = [
    "authorization", "x-api-key", "x-auth-token", "x-csrf-token",
    "set-cookie", "access-control-allow-credentials",
]


def _cors_request(url: str, origin: str, headers: dict,
                  method: str = "GET") -> requests.Response:
    h = {**UA, **headers, "Origin": origin}
    return requests.request(method, url, headers=h,
                            timeout=TIMEOUT, verify=False, allow_redirects=False)


def scan(url: str, *, cookie: str = "", extra_headers: dict | None = None) -> list[dict]:
    findings: list[dict] = []
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    scheme = parsed.scheme

    base_headers = {**UA}
    if cookie:
        base_headers["Cookie"] = cookie
    if extra_headers:
        base_headers.update(extra_headers)

    # ── 1. Wildcard ────────────────────────────────────────────────────────
    try:
        r = _cors_request(url, "https://evil.com", base_headers)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*":
            findings.append({
                "name": "CORS Wildcard Origin",
                "severity": "medium",
                "detail": "Access-Control-Allow-Origin: * — credentials cannot be sent, but data is exposed to any origin",
                "header": f"ACAO: {acao}",
            })
        if acao == "*" and acac.lower() == "true":
            findings.append({
                "name": "CORS Wildcard + Credentials (invalid but present)",
                "severity": "high",
                "detail": "ACAO: * with ACAC: true is invalid per spec but some browsers may honour it",
            })
    except requests.RequestException:
        pass

    # ── 2. Arbitrary origin reflection ─────────────────────────────────────
    attacker_origin = "https://attacker.com"
    try:
        r = _cors_request(url, attacker_origin, base_headers)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == attacker_origin:
            sev = "critical" if acac.lower() == "true" else "high"
            findings.append({
                "name": "CORS Arbitrary Origin Reflected",
                "severity": sev,
                "detail": (
                    f"Server reflects any Origin. ACAC={acac!r}. "
                    "Attacker can read credentialed responses cross-origin."
                    if acac.lower() == "true" else
                    f"Server reflects arbitrary Origin without credentials."
                ),
                "header": f"ACAO: {acao}  ACAC: {acac}",
            })
    except requests.RequestException:
        pass

    # ── 3. Null origin ─────────────────────────────────────────────────────
    try:
        r = _cors_request(url, "null", base_headers)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "null":
            findings.append({
                "name": "CORS Null Origin Trusted",
                "severity": "high",
                "detail": (
                    "Server allows 'null' origin. Sandboxed iframes and "
                    "local file:// pages can send credentialed requests."
                ),
            })
    except requests.RequestException:
        pass

    # ── 4. Subdomain trust ─────────────────────────────────────────────────
    subdomain_origins = [
        f"https://evil.{host}",
        f"https://attacker.{host}",
        f"https://sub.{host}",
        f"https://{host}.evil.com",
        f"https://{host}evil.com",
        f"http://{host}",   # protocol downgrade
    ]
    for origin in subdomain_origins:
        try:
            r = _cors_request(url, origin, base_headers)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            if acao == origin:
                is_proto = origin.startswith("http://")
                findings.append({
                    "name": (
                        "CORS HTTP Origin Trusted (Protocol Downgrade)"
                        if is_proto else "CORS Subdomain Injection"
                    ),
                    "severity": "high",
                    "detail": f"Origin {origin!r} accepted → ACAO: {acao}",
                })
        except requests.RequestException:
            continue

    # ── 5. Pre-flight OPTIONS bypass ───────────────────────────────────────
    try:
        r = requests.options(
            url,
            headers={
                **base_headers,
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "DELETE",
                "Access-Control-Request-Headers": "Authorization",
            },
            timeout=TIMEOUT, verify=False, allow_redirects=False,
        )
        acam = r.headers.get("Access-Control-Allow-Methods", "")
        acah = r.headers.get("Access-Control-Allow-Headers", "")
        if "DELETE" in acam or "PUT" in acam or "PATCH" in acam:
            findings.append({
                "name": "CORS Pre-flight Allows Dangerous Methods",
                "severity": "medium",
                "detail": f"ACAM: {acam}",
            })
        if "authorization" in acah.lower():
            findings.append({
                "name": "CORS Pre-flight Allows Authorization Header",
                "severity": "medium",
                "detail": f"ACAH: {acah}",
            })
    except requests.RequestException:
        pass

    # ── 6. Exposed sensitive response headers ──────────────────────────────
    try:
        r = requests.get(url, headers=base_headers, timeout=TIMEOUT,
                         verify=False, allow_redirects=False)
        acao = r.headers.get("Access-Control-Expose-Headers", "")
        exposed = [h for h in acao.lower().split(",")
                   if any(s in h for s in SENSITIVE_RESP_HEADERS)]
        if exposed:
            findings.append({
                "name": "CORS Exposes Sensitive Headers",
                "severity": "medium",
                "detail": f"Access-Control-Expose-Headers includes: {', '.join(exposed)}",
            })
        if not findings:
            findings.append({
                "name": "No CORS Misconfiguration Found",
                "severity": "info",
                "detail": "All tested CORS scenarios appear properly restricted",
            })
    except requests.RequestException:
        pass

    return findings


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Catch403 CORS Scanner")
    parser.add_argument("-u", dest="url", required=True)
    parser.add_argument("--cookie", default="")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    parsed = urllib.parse.urlparse(args.url)
    print(f"{run} CORS scan: {bold}{parsed.netloc}{parsed.path}{end}\n")

    results = scan(args.url, cookie=args.cookie)
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

    crits = [f for f in results if f.get("severity") in ("critical", "high")]
    print()
    if crits:
        print(f"{good} {len(crits)} critical/high finding(s)")
    else:
        print(f"{info} CORS scan complete")


if __name__ == "__main__":
    main()
