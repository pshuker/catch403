"""Catch403 web server — exposes all tools via HTTP API."""
import importlib
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ensure project root is on path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import difflib
import base64
import html as _html
import urllib.parse
import statistics
import math
import zlib
import hmac as _hmac
import hashlib
from collections import Counter

INDEX = os.path.join(os.path.dirname(__file__), "index.html")


# ── tool implementations (inline so server is self-contained) ───────────────

def api_decoder(data):
    text  = data.get("input", "")
    mode  = data.get("mode", "url-decode")
    try:
        if mode == "url-encode":
            out = urllib.parse.quote(text, safe="")
        elif mode == "url-decode":
            out = urllib.parse.unquote(text)
        elif mode == "b64-encode":
            out = base64.b64encode(text.encode()).decode()
        elif mode == "b64-decode":
            out = base64.b64decode(text + "==").decode(errors="replace")
        elif mode == "html-encode":
            out = _html.escape(text)
        elif mode == "html-decode":
            out = _html.unescape(text)
        elif mode == "hex-encode":
            out = text.encode().hex()
        elif mode == "hex-decode":
            out = bytes.fromhex(text).decode(errors="replace")
        else:
            out = text
        return {"output": out}
    except Exception as e:
        return {"error": str(e)}


def _b64d(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def _b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def api_jwt_decode(data):
    token = data.get("token", "").strip()
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Not a valid JWT"}
    try:
        header  = json.loads(_b64d(parts[0]))
        payload = json.loads(_b64d(parts[1]))
        warnings = []
        alg = header.get("alg", "").upper()
        if alg in ("NONE", "") or not parts[2]:
            warnings.append("⚠ Token is unsigned (alg:none) — server may accept arbitrary claims")
        if alg.startswith("RS") or alg.startswith("EC"):
            warnings.append(f"ℹ Algorithm {alg}: test RS→HS key-confusion attack (see JWT tab)")
        if "exp" in payload:
            import time
            if payload["exp"] < time.time():
                warnings.append("⚠ Token is EXPIRED")
        return {"header": header, "payload": payload, "signature": parts[2], "warnings": warnings}
    except Exception as e:
        return {"error": str(e)}

def api_jwt_algnone(data):
    token = data.get("token", "").strip()
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Not a valid JWT"}
    try:
        header = json.loads(_b64d(parts[0]))
        header["alg"] = "none"
        h = _b64e(json.dumps(header, separators=(",",":")).encode())
        p = parts[1]
        return {"forged": f"{h}.{p}."}
    except Exception as e:
        return {"error": str(e)}

def api_jwt_tamper(data):
    token  = data.get("token", "").strip()
    claims = data.get("claims", {})
    parts  = token.split(".")
    if len(parts) != 3:
        return {"error": "Not a valid JWT"}
    try:
        header  = json.loads(_b64d(parts[0]))
        payload = json.loads(_b64d(parts[1]))
        for k, v in claims.items():
            try:
                payload[k] = json.loads(v)
            except Exception:
                payload[k] = v
        h = _b64e(json.dumps(header,  separators=(",",":")).encode())
        p = _b64e(json.dumps(payload, separators=(",",":")).encode())
        return {"forged": f"{h}.{p}."}
    except Exception as e:
        return {"error": str(e)}

def api_jwt_crack(data):
    token    = data.get("token", "").strip()
    wordlist = data.get("wordlist", "")
    parts    = token.split(".")
    if len(parts) != 3:
        return {"error": "Not a valid JWT"}
    try:
        header = json.loads(_b64d(parts[0]))
        alg    = header.get("alg", "").upper()
        hmap   = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        h_fn   = hmap.get(alg)
        if not h_fn:
            return {"error": f"crack only supports HMAC. Token uses {alg}"}
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected      = _b64d(parts[2])
        for line in wordlist.splitlines():
            secret    = line.strip().encode()
            candidate = _hmac.new(secret, signing_input, h_fn).digest()
            if _hmac.compare_digest(candidate, expected):
                return {"found": secret.decode(errors="replace")}
        return {"found": None, "message": "Secret not found in wordlist"}
    except Exception as e:
        return {"error": str(e)}

def api_compare(data):
    a = data.get("a", "").splitlines(keepends=True)
    b = data.get("b", "").splitlines(keepends=True)
    diff = list(difflib.unified_diff(a, b, fromfile="A", tofile="B", lineterm=""))
    ratio = difflib.SequenceMatcher(None, a, b).ratio()
    return {"diff": "\n".join(diff), "similarity": round(ratio * 100, 1)}

def api_csrf(data):
    request_text = data.get("request", "")
    import re
    from urllib.parse import unquote as _unquote
    lines = request_text.strip().splitlines()
    if not lines:
        return {"error": "Empty request"}
    method, resource = lines[0].split()[0], lines[0].split()[1]
    headers_dict = {}
    body = ""
    in_body = False
    for line in lines[1:]:
        if not in_body:
            if line.strip() == "":
                in_body = True
            elif ":" in line:
                k, _, v = line.partition(":")
                headers_dict[k.strip()] = v.strip()
        else:
            body += line
    host   = headers_dict.get("Host", "")
    origin = headers_dict.get("Origin", "")
    proto  = re.search(r"(https?://)", origin).group(1) if origin else "https://"
    url    = f"{proto}{host}{resource}"
    body   = _unquote(body.strip())
    inputs = []
    for param in body.split("&"):
        if "=" in param:
            n, _, v = param.partition("=")
            inputs.append(f'        <input type="hidden" name="{_html.escape(n)}" value="{_html.escape(v)}">')
    poc = f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body>
    <form method="{method}" action="{_html.escape(url)}">
{chr(10).join(inputs)}
    </form>
    <script>document.forms[0].submit();</script>
</body>
</html>"""
    return {"poc": poc, "url": url}

def _shannon(token):
    if not token: return 0.0
    counts = Counter(token)
    n = len(token)
    return -sum((c/n)*math.log2(c/n) for c in counts.values())

def api_sequencer(data):
    tokens = [t.strip() for t in data.get("tokens", "").splitlines() if t.strip()]
    if len(tokens) < 2:
        return {"error": "Provide at least 2 tokens (one per line)"}
    entropies    = [_shannon(t) for t in tokens]
    avg_entropy  = statistics.mean(entropies)
    lengths      = [len(t) for t in tokens]
    bits         = "".join(format(ord(c),"08b") for t in tokens for c in t)
    ones         = bits.count("1")
    bit_ent      = 0.0
    if bits:
        p = ones/len(bits)
        if 0 < p < 1:
            bit_ent = -(p*math.log2(p)+(1-p)*math.log2(1-p))
    joined       = "\n".join(tokens).encode()
    comp_ratio   = len(zlib.compress(joined,9))/len(joined) if joined else 1.0
    n            = len(bits)
    monobit_s    = abs(ones-(n-ones))/math.sqrt(n) if n else 0
    monobit_pass = monobit_s < 1.96
    unique_ratio = len(set(tokens))/len(tokens)
    score = sum([avg_entropy>=3.5, bit_ent>=0.9, comp_ratio>=0.85, monobit_pass, unique_ratio>=0.99])
    verdict = "STRONG" if score>=4 else ("MODERATE" if score>=2 else "WEAK")
    return {
        "count": len(tokens), "avg_entropy": round(avg_entropy,4),
        "bit_entropy": round(bit_ent,4), "compression_ratio": round(comp_ratio,3),
        "monobit_pass": monobit_pass, "monobit_s": round(monobit_s,3),
        "unique_ratio": round(unique_ratio*100,1),
        "min_length": min(lengths), "max_length": max(lengths),
        "avg_length": round(statistics.mean(lengths),1),
        "score": score, "verdict": verdict,
    }

def api_spider(data):
    import urllib.request as _ureq, urllib.error as _uerr
    import html.parser as _hparser, time as _time

    url   = data.get("url", "").strip()
    depth = int(data.get("depth", 2))

    class LP(_hparser.HTMLParser):
        def __init__(self): super().__init__(); self.links=[]
        def handle_starttag(self, tag, attrs):
            m = dict(attrs)
            for a in ("href","src","action"):
                if m.get(a): self.links.append(m[a])

    from collections import deque
    parsed   = urllib.parse.urlparse(url)
    base     = parsed.netloc
    visited, external, files, errors = set(), set(), set(), {}
    queue    = deque([(url, 0)])
    FILE_EXT = {".pdf",".png",".jpg",".jpeg",".gif",".svg",".ico",".zip",".mp4",".mp3"}
    UA       = "Mozilla/5.0 (compatible; Catch403Spider/1.0)"

    while queue:
        cur, d = queue.popleft()
        cur = cur.split("#")[0]
        if cur in visited or d > depth: continue
        visited.add(cur)
        ext = os.path.splitext(urllib.parse.urlparse(cur).path)[1].lower()
        if ext in FILE_EXT:
            files.add(cur); continue
        req = _ureq.Request(cur, headers={"User-Agent": UA})
        try:
            with _ureq.urlopen(req, timeout=8) as r:
                body = r.read(500_000)
                ct   = r.headers.get("Content-Type","")
        except _uerr.HTTPError as e:
            errors[cur] = f"HTTP {e.code}"; continue
        except Exception as e:
            errors[cur] = str(e); continue
        if "text/html" not in ct: continue
        lp = LP(); lp.feed(body.decode(errors="replace"))
        for link in lp.links:
            full = urllib.parse.urljoin(cur, link).split("#")[0]
            if not full or full in visited: continue
            if urllib.parse.urlparse(full).netloc == base:
                queue.append((full, d+1))
            else:
                external.add(full)

    return {"visited": sorted(visited), "external": sorted(external),
            "files": sorted(files), "errors": errors}

def api_params(data):
    import requests as _req
    from bs4 import BeautifulSoup as _BS
    url      = data.get("url","").strip()
    wordlist = data.get("wordlist","")
    if not url: return {"error": "No URL provided"}
    params   = [l.strip() for l in wordlist.splitlines() if l.strip()] if wordlist else []
    if not params:
        wl = os.path.join(ROOT, "modules", "common-params.txt")
        with open(wl) as f: params = [l.strip() for l in f if l.strip()]
    UA = {"User-Agent":"Mozilla/5.0"}
    try:
        base_len = len(_BS(_req.get(url,headers=UA,timeout=8).content,"lxml").text)
    except Exception as e:
        return {"error": str(e)}
    found = []
    for p in params:
        try:
            r = _req.get(url, headers=UA, params={p:"1"}, timeout=8)
            if len(_BS(r.content,"lxml").text) != base_len:
                found.append(p)
        except Exception:
            pass
    return {"found": found, "tested": len(params)}


# ── HTTP handler ────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence default logging

    def _send(self, code, body, ct="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", len(data))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, result):
        self._send(200, json.dumps(result))

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            with open(INDEX, "rb") as f: body = f.read()
            self._send(200, body, "text/html")
        else:
            self._send(404, b"Not found", "text/plain")

    def do_POST(self):
        data = self._read_body()
        routes = {
            "/api/decoder":    api_decoder,
            "/api/jwt/decode": api_jwt_decode,
            "/api/jwt/algnone":api_jwt_algnone,
            "/api/jwt/tamper": api_jwt_tamper,
            "/api/jwt/crack":  api_jwt_crack,
            "/api/compare":    api_compare,
            "/api/csrf":       api_csrf,
            "/api/sequencer":  api_sequencer,
            "/api/spider":     api_spider,
            "/api/params":     api_params,
        }
        handler = routes.get(self.path)
        if handler:
            self._json(handler(data))
        else:
            self._send(404, json.dumps({"error": "Unknown endpoint"}))


def run(host="127.0.0.1", port=8888):
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"  Catch403 running → http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8888)
    a = p.parse_args()
    run(a.host, a.port)
