#!/usr/bin/python3
"""
Intercepting Proxy — HTTP/HTTPS MITM proxy server.
The core of catch403. Configure your browser to use localhost:8080.

Features:
  - HTTP transparent forwarding + logging
  - HTTPS via CONNECT tunnel with dynamic per-domain SSL certs
  - On-the-fly CA cert generation (import ca.crt into your browser)
  - Traffic logged to ~/.catch403/traffic.db (Logger++)
  - Scope-aware: only logs in-scope URLs
  - Auto Repeater integration: matching rules auto-resend requests
  - Intercept queue: pause requests for manual inspection via web UI

CA setup (one-time):
  - Start the proxy → it generates ~/.catch403/ca/ca.crt
  - Import ca.crt into your browser's certificate store
  - Set browser proxy: localhost:8080

Usage:
  ../.venv/bin/python3 modules/intercepting_proxy.py
  ../.venv/bin/python3 modules/intercepting_proxy.py --port 8080 --no-verify
  ../.venv/bin/python3 modules/intercepting_proxy.py --port 8080 --scope target.com
"""
import argparse
import io
import os
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import requests
import urllib3

# Lazy import — cryptography only needed for CA setup
_crypto_ok = False
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime as _dt
    _crypto_ok = True
except ImportError:
    pass

from core.colors import bold, end, green, yellow, red, run, good, bad, info

urllib3.disable_warnings()

CA_DIR   = os.path.expanduser("~/.catch403/ca")
CA_KEY   = os.path.join(CA_DIR, "ca.key")
CA_CRT   = os.path.join(CA_DIR, "ca.crt")
CERT_DIR = os.path.join(CA_DIR, "certs")

_cert_cache: dict[str, tuple[str, str]] = {}
_ca_key_obj = _ca_cert_obj = None

# Shared intercept queue (web UI polls this)
intercept_queue: list[dict] = []
intercept_lock  = threading.Lock()

# Traffic log (optional, loaded lazily)
_traffic_log = None

def _get_log():
    global _traffic_log
    if _traffic_log is None:
        try:
            from modules.logger_plus import TrafficLog
            _traffic_log = TrafficLog()
        except Exception:
            pass
    return _traffic_log


# ── CA and cert generation ─────────────────────────────────────────────────

def _setup_ca():
    global _ca_key_obj, _ca_cert_obj
    if not _crypto_ok:
        print(f"{bad} cryptography library not installed. Run: pip install cryptography")
        sys.exit(1)

    os.makedirs(CA_DIR, exist_ok=True)
    os.makedirs(CERT_DIR, exist_ok=True)

    if os.path.exists(CA_KEY) and os.path.exists(CA_CRT):
        with open(CA_KEY, "rb") as f:
            _ca_key_obj = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CRT, "rb") as f:
            _ca_cert_obj = x509.load_pem_x509_certificate(f.read())
        print(f"{good} CA loaded: {CA_CRT}")
        return

    print(f"{run} Generating CA certificate…")
    _ca_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Catch403 CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Catch403"),
    ])
    now  = _dt.datetime.now(_dt.timezone.utc)
    _ca_cert_obj = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(_ca_key_obj.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(_ca_key_obj.public_key()), critical=False)
        .sign(_ca_key_obj, hashes.SHA256())
    )

    with open(CA_KEY, "wb") as f:
        f.write(_ca_key_obj.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(CA_CRT, "wb") as f:
        f.write(_ca_cert_obj.public_bytes(serialization.Encoding.PEM))

    print(f"{good} CA generated: {green}{CA_CRT}{end}")
    print(f"{info} {bold}Import {CA_CRT} into your browser's certificate store to trust HTTPS.{end}")


def _cert_for_host(hostname: str) -> tuple[str, str]:
    if hostname in _cert_cache:
        return _cert_cache[hostname]

    key_path  = os.path.join(CERT_DIR, f"{hostname}.key")
    cert_path = os.path.join(CERT_DIR, f"{hostname}.crt")

    if not os.path.exists(cert_path):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        now  = _dt.datetime.now(_dt.timezone.utc)
        san  = x509.SubjectAlternativeName([x509.DNSName(hostname), x509.DNSName(f"*.{hostname}")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(_ca_cert_obj.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + _dt.timedelta(days=825))
            .add_extension(san, critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .sign(_ca_key_obj, hashes.SHA256())
        )
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    _cert_cache[hostname] = (cert_path, key_path)
    return cert_path, key_path


# ── Proxy handler ──────────────────────────────────────────────────────────

class ProxyHandler(BaseHTTPRequestHandler):
    timeout = 20
    _intercept_enabled = False
    _scope_host: str | None = None

    def log_message(self, fmt, *args):
        pass   # suppress default access log

    def _in_scope(self, url: str) -> bool:
        if not self._scope_host:
            return True
        from urllib.parse import urlparse
        host = urlparse(url).netloc.split(":")[0]
        return self._scope_host in host

    def _forward(self, method: str, url: str, headers: dict,
                 body: bytes | None, scheme: str = "https") -> tuple[int, dict, bytes]:
        h = {k: v for k, v in headers.items()
             if k.lower() not in ("proxy-connection", "proxy-authorization")}
        h.setdefault("User-Agent", "Mozilla/5.0")
        t0 = time.perf_counter()
        try:
            r = requests.request(method, url, headers=h, data=body,
                                 timeout=self.timeout, verify=False,
                                 allow_redirects=False, stream=False)
            elapsed = int((time.perf_counter() - t0) * 1000)
            return r.status_code, dict(r.headers), r.content, elapsed
        except Exception as e:
            elapsed = int((time.perf_counter() - t0) * 1000)
            return 502, {}, str(e).encode(), elapsed

    def _send_response_to_client(self, status: int, resp_headers: dict, body: bytes):
        self.send_response(status)
        hop_by_hop = {"transfer-encoding", "connection", "keep-alive",
                      "proxy-authenticate", "te", "trailers", "upgrade"}
        for k, v in resp_headers.items():
            if k.lower() not in hop_by_hop:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _log_traffic(self, method: str, url: str, req_headers: dict, req_body: bytes,
                     status: int, resp_headers: dict, resp_body: bytes, elapsed: int):
        log = _get_log()
        if log and self._in_scope(url):
            try:
                log.record(method, url, req_headers, req_body,
                           status, resp_headers, resp_body, elapsed)
            except Exception:
                pass
        # Console
        sc_col = green if status < 300 else (yellow if status < 400 else red)
        print(f"  {sc_col}[{status}]{end}  {method:<6}  {url[:80]}"
              f"  {len(resp_body)}B  {elapsed}ms")

    def do_CONNECT(self):
        """Handle HTTPS CONNECT tunnel."""
        host, _, port_s = self.path.partition(":")
        port = int(port_s or 443)

        self.send_response(200, "Connection Established")
        self.end_headers()

        # Wrap the client socket in SSL using a per-host cert
        try:
            cert_path, key_path = _cert_for_host(host)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_path, key_path)
            ssl_sock = ctx.wrap_socket(self.connection, server_side=True)
        except Exception as e:
            print(f"{bad} SSL error for {host}: {e}")
            return

        # Parse the inner HTTP request
        try:
            rfile = ssl_sock.makefile("rb")
            request_line = rfile.readline().decode(errors="replace").strip()
            if not request_line:
                return

            parts = request_line.split(" ", 2)
            if len(parts) < 2:
                return
            method, path = parts[0], parts[1]

            headers = {}
            while True:
                line = rfile.readline().decode(errors="replace").strip()
                if not line:
                    break
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip()] = v.strip()

            body = None
            cl = int(headers.get("Content-Length", headers.get("content-length", 0)))
            if cl > 0:
                body = rfile.read(cl)

            url = f"https://{host}:{port}{path}"

            status, resp_headers, resp_body, elapsed = self._forward(
                method, url, headers, body, scheme="https"
            )
            self._log_traffic(method, url, headers, body or b"",
                              status, resp_headers, resp_body, elapsed)

            # Send response back over SSL connection
            response = f"HTTP/1.1 {status} OK\r\n"
            hop_by_hop = {"transfer-encoding", "connection", "keep-alive"}
            for k, v in resp_headers.items():
                if k.lower() not in hop_by_hop:
                    response += f"{k}: {v}\r\n"
            response += f"Content-Length: {len(resp_body)}\r\n\r\n"
            ssl_sock.sendall(response.encode() + resp_body)

        except Exception as e:
            pass
        finally:
            try:
                ssl_sock.close()
            except Exception:
                pass

    def _handle_http(self):
        """Handle plain HTTP proxy request."""
        method  = self.command
        url     = self.path
        if not url.startswith("http"):
            url = f"http://{self.headers.get('Host','')}{url}"

        headers = dict(self.headers)
        body    = None
        cl = int(headers.get("Content-Length", headers.get("content-length", 0)))
        if cl > 0:
            body = self.rfile.read(cl)

        status, resp_headers, resp_body, elapsed = self._forward(
            method, url, headers, body, scheme="http"
        )
        self._log_traffic(method, url, headers, body or b"",
                          status, resp_headers, resp_body, elapsed)
        self._send_response_to_client(status, resp_headers, resp_body)

    # Map all methods to HTTP handler
    do_GET     = _handle_http
    do_POST    = _handle_http
    do_PUT     = _handle_http
    do_PATCH   = _handle_http
    do_DELETE  = _handle_http
    do_HEAD    = _handle_http
    do_OPTIONS = _handle_http


# ── Server ─────────────────────────────────────────────────────────────────

class ProxyServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080,
                 scope_host: str | None = None):
        self.host       = host
        self.port       = port
        self.scope_host = scope_host
        self._server: ThreadingHTTPServer | None = None

    def start(self, block: bool = True):
        _setup_ca()

        ProxyHandler._scope_host = self.scope_host

        self._server = ThreadingHTTPServer((self.host, self.port), ProxyHandler)
        self._server.daemon_threads = True

        print(f"\n{bold}Catch403 Intercepting Proxy{end}")
        print(f"  {info} Listening  : {green}http://{self.host}:{self.port}{end}")
        print(f"  {info} CA cert    : {CA_CRT}")
        print(f"  {info} Traffic log: ~/.catch403/traffic.db")
        if self.scope_host:
            print(f"  {info} Scope      : {self.scope_host}")
        print(f"\n  {bold}Configure your browser proxy: {self.host}:{self.port}{end}")
        print(f"  Import {CA_CRT} into browser certificates to trust HTTPS.\n")

        if block:
            try:
                self._server.serve_forever()
            except KeyboardInterrupt:
                print(f"\n{bad} Proxy stopped")
        else:
            t = threading.Thread(target=self._server.serve_forever, daemon=True)
            t.start()

    def stop(self):
        if self._server:
            self._server.shutdown()


def main():
    parser = argparse.ArgumentParser(description="HTTP/HTTPS intercepting MITM proxy")
    parser.add_argument("--host",  default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port",  type=int, default=8080, help="Proxy port (default: 8080)")
    parser.add_argument("--scope", dest="scope_host",
                        help="Only log traffic to this host (e.g. target.com)")
    parser.add_argument("--ca-info", action="store_true",
                        help="Show CA cert path and exit")
    args = parser.parse_args()

    if args.ca_info:
        print(f"CA cert : {CA_CRT}")
        print(f"CA key  : {CA_KEY}")
        print(f"Cert dir: {CERT_DIR}")
        return

    server = ProxyServer(args.host, args.port, args.scope_host)
    server.start(block=True)


if __name__ == "__main__":
    main()
