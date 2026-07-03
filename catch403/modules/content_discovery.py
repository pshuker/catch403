#!/usr/bin/python3
"""
Content Discovery — directory and file brute-forcer.
Inspired by feroxbuster, gobuster, and dirbuster.

Features:
  - Multi-threaded (default 20 threads)
  - Extension fuzzing (.php, .bak, .html, etc.)
  - Recursive discovery on 200/301
  - Wildcard/false-positive detection
  - Custom status code filtering
  - Built-in mini-wordlist (~220 paths); use -w for full lists

Usage:
  ../.venv/bin/python3 modules/content_discovery.py -u https://target.com
  ../.venv/bin/python3 modules/content_discovery.py -u https://target.com -w /usr/share/wordlists/dirb/common.txt
  ../.venv/bin/python3 modules/content_discovery.py -u https://target.com -e php,bak,txt -t 40 -r
"""
import argparse
import queue
import re
import threading
import time
from urllib.parse import urljoin, urlparse

import requests
import urllib3

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab
from core.auth_gate import preflight

urllib3.disable_warnings()

UA = "Mozilla/5.0 (compatible; Catch403/1.0)"

BUILTIN_WORDLIST = """
.git .git/HEAD .git/config .svn .env .env.bak .htaccess .htpasswd
robots.txt sitemap.xml crossdomain.xml security.txt
admin admin/ administrator login logout register signup
api api/v1 api/v2 api/v3 graphql rest swagger swagger.json
config config.php config.ini config.yml config.json settings
backup backup/ backups bak db database
upload uploads files media static assets
test testing debug phpmyadmin pma adminer
wp-admin wp-login.php wp-config.php xmlrpc.php
dashboard panel control cp
index.php index.html index.htm default.asp default.aspx
error error.log access.log debug.log application.log
console shell cmd exec command
user users account accounts profile
info information about contact
search query include src scripts js css
vendor composer.json package.json Gemfile requirements.txt
server-status server-info .DS_Store Thumbs.db
auth token oauth2 callback redirect
v1 v2 v3 health ping status version
private public internal external hidden
old archive tmp temp cache
readme README.md CHANGELOG TODO LICENSE
""".split()


def _normalize(url: str) -> str:
    if not url.startswith("http"):
        url = "https://" + url
    return url.rstrip("/")


def _wildcard_fingerprint(base_url: str, session: requests.Session) -> str | None:
    """Detect wildcard 200 responses — if a random path returns 200, filter it."""
    import random, string
    rand_path = "/" + "".join(random.choices(string.ascii_lowercase, k=16))
    try:
        r = session.get(base_url + rand_path, timeout=8, allow_redirects=True)
        if r.status_code == 200:
            # Fingerprint by length to filter false positives
            return str(len(r.text))
    except Exception:
        pass
    return None


class ContentDiscovery:
    def __init__(self, base_url: str, wordlist: list[str],
                 extensions: list[str] | None = None,
                 threads: int = 20, recursive: bool = False,
                 status_filter: set[int] | None = None,
                 timeout: int = 8, cookies: dict | None = None):
        self.base_url   = _normalize(base_url)
        self.wordlist   = wordlist
        self.extensions = extensions or []
        self.threads    = threads
        self.recursive  = recursive
        self.timeout    = timeout
        self.status_filter = status_filter or {200, 201, 204, 301, 302, 307, 401, 403}

        self.session = requests.Session()
        self.session.headers["User-Agent"] = UA
        self.session.verify = False
        if cookies:
            self.session.cookies.update(cookies)

        self.results:   list[dict] = []
        self._lock      = threading.Lock()
        self._q:        queue.Queue = queue.Queue()
        self._visited:  set[str]   = set()
        self._wildcard: str | None = None
        self._done      = 0
        self._total     = 0

    def _build_paths(self, base: str, word: str) -> list[str]:
        paths = [f"{base}/{word}"]
        for ext in self.extensions:
            e = ext.lstrip(".")
            paths.append(f"{base}/{word}.{e}")
        return paths

    def _probe(self, url: str) -> dict | None:
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            if r.status_code not in self.status_filter:
                return None
            # Wildcard filter
            if self._wildcard and str(len(r.text)) == self._wildcard and r.status_code == 200:
                return None
            return {
                "url":     url,
                "status":  r.status_code,
                "length":  len(r.content),
                "redirect": r.headers.get("Location", ""),
                "ct":      r.headers.get("Content-Type","").split(";")[0],
            }
        except Exception:
            return None

    def _worker(self):
        while True:
            item = self._q.get()
            if item is None:
                break
            url = item
            result = self._probe(url)
            with self._lock:
                self._done += 1
                if result:
                    self.results.append(result)
                    _print_result(result)
                    # Recurse into directories
                    if self.recursive and result["status"] in (200, 301, 302):
                        next_base = url.rstrip("/")
                        if next_base not in self._visited:
                            self._visited.add(next_base)
                            self._enqueue(next_base)
            self._q.task_done()

    def _enqueue(self, base: str):
        for word in self.wordlist:
            for path in self._build_paths(base, word):
                if path not in self._visited:
                    self._visited.add(path)
                    self._q.put(path)
                    self._total += 1

    def run(self) -> list[dict]:
        print(f"\n{bold}Content Discovery{end} → {self.base_url}")
        print(f"  {info} Wordlist : {len(self.wordlist)} words"
              f"{'  +exts: ' + ','.join(self.extensions) if self.extensions else ''}")
        print(f"  {info} Threads  : {self.threads}")
        print(f"  {info} Status   : {sorted(self.status_filter)}\n")

        self._wildcard = _wildcard_fingerprint(self.base_url, self.session)
        if self._wildcard:
            print(f"  {info} Wildcard 200 detected (len={self._wildcard}) — filtering false positives\n")

        self._enqueue(self.base_url)
        workers = [threading.Thread(target=self._worker, daemon=True) for _ in range(self.threads)]
        for w in workers: w.start()

        t0 = time.time()
        try:
            self._q.join()
        except KeyboardInterrupt:
            print(f"\n{bad} Interrupted")
        finally:
            for _ in workers: self._q.put(None)
            for w in workers: w.join(timeout=1)

        elapsed = time.time() - t0
        print(f"\n{bold}Found {len(self.results)} paths in {elapsed:.1f}s{end}")
        return self.results


def _status_col(s: int) -> str:
    if s < 300:   return green
    if s < 400:   return yellow
    return red


def _print_result(r: dict):
    sc = _status_col(r["status"])
    redir = f"  → {r['redirect']}" if r["redirect"] else ""
    print(f"  {sc}[{r['status']}]{end}  {r['url']:<65}  {r['length']:>7}B{redir}")


def main():
    from modules.wordlists import WL, add_wordlist_arg
    parser = argparse.ArgumentParser(description="Directory and file brute-forcer")
    parser.add_argument("-u",  dest="url",       required=True, help="Target base URL")
    add_wordlist_arg(parser, "paths")
    parser.add_argument("-e",  dest="extensions",default="",
                        help="Extensions to append, comma-separated (e.g. php,txt,bak)")
    parser.add_argument("-t",  dest="threads",   type=int, default=20)
    parser.add_argument("-r",  dest="recursive", action="store_true", help="Recursive discovery")
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--status",  default="",
                        help="Custom status codes to show, comma-sep (e.g. 200,301,403)")
    parser.add_argument("--cookie",  default="", help="Cookie string (key=val; key2=val2)")
    parser.add_argument("-o",  dest="output", help="Save JSON results to file")
    args = parser.parse_args()

    preflight('content_discovery', args.url, active=True)

    wordlist = (WL.resolve(args.wordlist, "paths") if args.wordlist
                else WL.paths()) or BUILTIN_WORDLIST

    extensions = [e.strip() for e in args.extensions.split(",") if e.strip()]

    status_filter = None
    if args.status:
        try:
            status_filter = {int(s.strip()) for s in args.status.split(",") if s.strip()}
        except ValueError:
            pass

    cookies = {}
    if args.cookie:
        for part in args.cookie.split(";"):
            k, _, v = part.strip().partition("=")
            cookies[k] = v

    disc = ContentDiscovery(
        args.url, wordlist, extensions,
        threads=args.threads, recursive=args.recursive,
        status_filter=status_filter, timeout=args.timeout,
        cookies=cookies or None,
    )
    results = disc.run()

    if args.output:
        import json
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"{good} Results saved → {args.output}")


if __name__ == "__main__":
    main()
