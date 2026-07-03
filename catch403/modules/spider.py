#!/usr/bin/python3
"""
Spider — crawls a target and builds a site map. Stdlib only (no requests).

Follows in-scope links, records all URLs found (internal, external, files),
and outputs a site map. Respects a configurable depth limit and scope.

Usage:
  ../.venv/bin/python3 modules/spider.py -u https://target.com
  ../.venv/bin/python3 modules/spider.py -u https://target.com -d 3 -o sitemap.txt
"""
import argparse
import html.parser
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab
from core.auth_gate import preflight


DEFAULT_UA = "Mozilla/5.0 (compatible; Catch403Spider/1.0)"


# ── link extractor ─────────────────────────────────────────────────────────

class _LinkParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        attr_map = dict(attrs)
        for attr in ("href", "src", "action"):
            if attr in attr_map and attr_map[attr]:
                self.links.append(attr_map[attr])


def _extract_links(html_bytes: bytes, base_url: str) -> list[str]:
    try:
        text = html_bytes.decode("utf-8", errors="replace")
    except Exception:
        return []
    parser = _LinkParser()
    parser.feed(text)
    resolved = []
    for link in parser.links:
        link = link.strip()
        if not link or link.startswith("#") or link.startswith("javascript:"):
            continue
        resolved.append(urllib.parse.urljoin(base_url, link))
    return resolved


def _is_in_scope(url: str, base_host: str) -> bool:
    return urllib.parse.urlparse(url).netloc == base_host


FILE_EXTS = {".pdf", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
             ".zip", ".gz", ".tar", ".mp4", ".mp3", ".woff", ".woff2", ".ttf"}


def _is_file(url: str) -> bool:
    path = urllib.parse.urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in FILE_EXTS)


# ── crawler ────────────────────────────────────────────────────────────────

def crawl(start_url: str, max_depth: int = 2, delay: float = 0.0,
          verbose: bool = False) -> dict:
    parsed     = urllib.parse.urlparse(start_url)
    base_host  = parsed.netloc

    visited:  set[str]          = set()
    external: set[str]          = set()
    files:    set[str]          = set()
    errors:   dict[str, str]    = {}
    queue:    deque             = deque([(start_url, 0)])

    print(f"{run} {bold}Spider starting{end}: {start_url}  (depth≤{max_depth})")

    while queue:
        url, depth = queue.popleft()
        url = url.split("#")[0]   # strip fragment
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        if _is_file(url):
            files.add(url)
            if verbose:
                print(f"{tab}{info} FILE: {url}")
            continue

        req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read(1_000_000)   # cap at 1 MB per page
                content_type = resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            errors[url] = f"HTTP {e.code}"
            if verbose:
                print(f"{tab}{bad} {red}{e.code}{end}: {url}")
            continue
        except Exception as e:
            errors[url] = str(e)
            if verbose:
                print(f"{tab}{bad} {red}ERR{end}: {url}")
            continue

        print(f"{tab}{good} {green}{url}{end}")

        if "text/html" not in content_type:
            continue

        for link in _extract_links(body, url):
            clean = link.split("#")[0]
            if not clean or clean in visited:
                continue
            if _is_in_scope(clean, base_host):
                queue.append((clean, depth + 1))
            else:
                external.add(clean)

        if delay:
            time.sleep(delay)

    return {
        "start":    start_url,
        "visited":  sorted(visited),
        "external": sorted(external),
        "files":    sorted(files),
        "errors":   errors,
    }


def print_summary(result: dict) -> None:
    print(f"\n{bold}{underline}Site Map Summary{end}")
    print(f"{tab}Internal pages : {green}{bold}{len(result['visited'])}{end}")
    print(f"{tab}External links : {yellow}{bold}{len(result['external'])}{end}")
    print(f"{tab}Files found    : {bold}{len(result['files'])}{end}")
    print(f"{tab}Errors         : {red}{bold}{len(result['errors'])}{end}")


def main():
    parser = argparse.ArgumentParser(description="Web spider — build a site map (authorised targets only)")
    parser.add_argument("-u", dest="url",     required=True, help="Start URL")
    parser.add_argument("-d", dest="depth",   type=int, default=2, help="Max crawl depth (default: 2)")
    parser.add_argument("-o", dest="output",  help="Save visited URLs to file")
    parser.add_argument("-s", dest="delay",   type=float, default=0.0, help="Delay between requests (secs)")
    parser.add_argument("-v", dest="verbose", action="store_true", help="Verbose (show errors/files)")
    args = parser.parse_args()

    preflight('spider', args.url, active=False)

    result = crawl(args.url, max_depth=args.depth, delay=args.delay, verbose=args.verbose)
    print_summary(result)

    if args.output:
        with open(args.output, "w") as f:
            for url in result["visited"]:
                f.write(url + "\n")
        print(f"\n{info} Site map saved to: {bold}{args.output}{end}")


if __name__ == "__main__":
    main()
