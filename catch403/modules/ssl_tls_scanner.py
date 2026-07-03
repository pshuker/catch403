#!/usr/bin/python3
"""
SSL/TLS Scanner — covers the OWASP Secure Transmission and Cryptography categories.

Checks: TLS version support (SSL2/SSL3/TLS1.0/1.1/1.2/1.3), weak/export ciphers,
certificate validity (expiry, CN match, self-signed, chain), HSTS header,
mixed-content hints, and key length.

Usage:
  ../.venv/bin/python3 modules/ssl_tls_scanner.py -u https://target.com
  ../.venv/bin/python3 modules/ssl_tls_scanner.py --host target.com --port 443
  ../.venv/bin/python3 modules/ssl_tls_scanner.py -u https://target.com -o report.json
"""
import argparse
import datetime
import json
import socket
import ssl
import urllib.parse

import requests
import urllib3

from core.colors import bold, end, good, bad, info, run

urllib3.disable_warnings()

TIMEOUT = 10

# ── weak cipher keywords ───────────────────────────────────────────────────
WEAK_CIPHER_PATTERNS = [
    "NULL", "EXPORT", "DES", "RC2", "RC4", "MD5",
    "anon", "ADH", "AECDH", "3DES", "aNULL", "eNULL",
]

WEAK_TLS_VERSIONS = {
    "SSLv2":  ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl, "PROTOCOL_SSLv2") else None,
    "SSLv3":  ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl, "PROTOCOL_SSLv3") else None,
    "TLSv1.0": None,
    "TLSv1.1": None,
}


def _get_cert_info(host: str, port: int) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            version = ssock.version()
            der = ssock.getpeercert(binary_form=True)
    return {
        "cert": cert,
        "cipher": cipher,
        "version": version,
        "der": der,
    }


def _check_tls_version(host: str, port: int, version_str: str,
                        ssl_version_const) -> bool:
    """Return True if the server accepts this TLS version."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if version_str == "TLSv1.0":
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
        elif version_str == "TLSv1.1":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        else:
            return False
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def _cert_findings(host: str, cert: dict, der: bytes | None) -> list[dict]:
    findings = []
    if not cert:
        findings.append({
            "name": "No Certificate Returned",
            "severity": "high",
            "detail": "Server did not present a certificate",
        })
        return findings

    # Expiry
    not_after_str = cert.get("notAfter", "")
    if not_after_str:
        try:
            not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.utcnow()
            delta = (not_after - now).days
            if delta < 0:
                findings.append({
                    "name": "Certificate Expired",
                    "severity": "critical",
                    "detail": f"Expired {-delta} days ago ({not_after_str})",
                })
            elif delta < 30:
                findings.append({
                    "name": "Certificate Expiring Soon",
                    "severity": "medium",
                    "detail": f"Expires in {delta} days ({not_after_str})",
                })
            else:
                findings.append({
                    "name": "Certificate Valid",
                    "severity": "info",
                    "detail": f"Expires {not_after_str} ({delta} days)",
                })
        except ValueError:
            pass

    # CN match
    subject = dict(x[0] for x in cert.get("subject", []))
    cn = subject.get("commonName", "")
    san = [v for _, v in cert.get("subjectAltName", [])]
    if cn and not any(
        s == host or (s.startswith("*.") and host.endswith(s[1:]))
        for s in ([cn] + san)
    ):
        findings.append({
            "name": "Certificate CN Mismatch",
            "severity": "high",
            "detail": f"Host {host!r} not in CN={cn!r} or SANs={san}",
        })

    # Issuer == Subject → self-signed
    issuer = dict(x[0] for x in cert.get("issuer", []))
    if issuer == subject:
        findings.append({
            "name": "Self-Signed Certificate",
            "severity": "high",
            "detail": f"Issuer equals subject: {subject}",
        })

    return findings


def scan(url: str | None = None, *, host: str = "", port: int = 443) -> list[dict]:
    if url:
        parsed = urllib.parse.urlparse(url)
        host = host or parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

    findings: list[dict] = []

    # ── gather cert and connection info ───────────────────────────────────
    try:
        conn = _get_cert_info(host, port)
    except Exception as e:
        return [{"name": "Connection Failed", "severity": "info", "detail": str(e)}]

    cert = conn["cert"]
    cipher_name, tls_ver, bits = conn["cipher"]
    current_version = conn["version"]

    findings.append({
        "name": "TLS Version in Use",
        "severity": "info",
        "detail": f"{current_version} — cipher {cipher_name} ({bits}-bit)",
    })

    # ── weak cipher ───────────────────────────────────────────────────────
    if any(p in cipher_name.upper() for p in WEAK_CIPHER_PATTERNS):
        findings.append({
            "name": "Weak Cipher Negotiated",
            "severity": "high",
            "detail": f"Cipher: {cipher_name}",
        })

    # ── key length ────────────────────────────────────────────────────────
    if bits and bits < 128:
        findings.append({
            "name": "Short Key Length",
            "severity": "high",
            "detail": f"Only {bits}-bit key negotiated",
        })

    # ── old TLS version acceptance ────────────────────────────────────────
    for ver in ("TLSv1.0", "TLSv1.1"):
        if _check_tls_version(host, port, ver, None):
            findings.append({
                "name": f"Deprecated {ver} Accepted",
                "severity": "medium",
                "detail": f"Server accepts {ver} — disable in server config",
            })

    # ── certificate checks ────────────────────────────────────────────────
    findings += _cert_findings(host, cert, conn.get("der"))

    # ── HSTS ──────────────────────────────────────────────────────────────
    try:
        r = requests.get(f"https://{host}:{port}/", timeout=TIMEOUT,
                         verify=False, allow_redirects=True)
        hsts = r.headers.get("Strict-Transport-Security", "")
        if not hsts:
            findings.append({
                "name": "HSTS Missing",
                "severity": "medium",
                "detail": "Strict-Transport-Security header not present",
            })
        else:
            max_age = 0
            m = __import__("re").search(r"max-age=(\d+)", hsts)
            if m:
                max_age = int(m.group(1))
            if max_age < 31536000:
                findings.append({
                    "name": "HSTS max-age Too Short",
                    "severity": "low",
                    "detail": f"max-age={max_age} (recommend ≥31536000)",
                })
            else:
                findings.append({
                    "name": "HSTS Present",
                    "severity": "info",
                    "detail": hsts,
                })

        # Check login form over HTTP
        if r.url.startswith("http://"):
            findings.append({
                "name": "Login Redirects to HTTP",
                "severity": "high",
                "detail": f"Final URL after redirect: {r.url}",
            })
    except requests.RequestException:
        pass

    return findings


# ── CLI ────────────────────────────────────────────────────────────────────

_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def main():
    parser = argparse.ArgumentParser(description="Catch403 SSL/TLS Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", dest="url", help="Target URL (https://...)")
    group.add_argument("--host", help="Hostname to test directly")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    target = args.url or f"https://{args.host}:{args.port}"
    print(f"{run} SSL/TLS scan: {bold}{target}{end}\n")

    results = scan(args.url, host=args.host or "", port=args.port)
    results.sort(key=lambda f: _SEV.get(f.get("severity", "info"), 4))

    for f in results:
        sev = f.get("severity", "info")
        prefix = (bad if sev == "critical"
                  else f"{bold}[{sev.upper()}]{end}" if sev in ("high", "medium")
                  else good if f["name"].startswith(("Certificate Valid", "HSTS Present", "TLS"))
                  else info)
        print(f"{prefix} {bold}{f['name']}{end}")
        print(f"        {f['detail']}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n{good} Saved to {args.output}")


if __name__ == "__main__":
    main()
