#!/usr/bin/python3
"""
Parameter Miner — adapted from RobertJonnyTiger/Hidden-Parameter-Injector.

Injects parameters from a wordlist one-by-one and detects those that
change the response length (revealing hidden/undocumented parameters).

Usage:
  ../.venv/bin/python3 modules/param_miner.py -u https://target/page
  ../.venv/bin/python3 modules/param_miner.py --urls urls.txt -f wordlist.txt
"""
import argparse
import json
import os

import requests
from bs4 import BeautifulSoup

from core.colors import bold, underline, end, red, green, run, good, bad, info, que, tab

DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "common-params.txt")
_REGISTRY_DEFAULT = "params"   # wordlists registry key

DEFAULT_HEADERS = {
    "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "DNT":             "1",
    "Connection":      "keep-alive",
}


def _page_length(url: str, headers: dict) -> int:
    r = requests.get(url, headers=headers, timeout=10)
    return len(BeautifulSoup(r.content, "lxml").text)


def mine(url: str, wordlist: str | list[str] = DEFAULT_WORDLIST,
         headers: dict | None = None, json_data: bool = False) -> list[str]:
    h = dict(DEFAULT_HEADERS)
    if headers:
        h.update(headers)
    if json_data:
        h["Content-Type"] = "application/json"

    if isinstance(wordlist, list):
        params = wordlist
    else:
        with open(wordlist, encoding="utf-8") as f:
            params = [line.strip() for line in f if line.strip()]

    print(f"{run} {bold}Injecting {len(params)} params into{end}: {url}")
    baseline = _page_length(url, h)
    found: list[str] = []

    for param in params:
        try:
            r = requests.get(url, headers=h, params={param: "1"}, timeout=10)
            length = len(BeautifulSoup(r.content, "lxml").text)
            if length != baseline:
                print(f"{tab}{good} {green}{bold}Hidden param found{end}: {param}")
                found.append(param)
        except Exception:
            pass

    if not found:
        print(f"{tab}{bad} No hidden parameters found.")
    return found


def main():
    from modules.wordlists import WL, add_wordlist_arg
    parser = argparse.ArgumentParser(description="Discover hidden HTTP parameters via wordlist injection")
    parser.add_argument("-u",       dest="url",      help="Target URL")
    parser.add_argument("--urls",   dest="url_file", help="File of target URLs (one per line)")
    add_wordlist_arg(parser, "params", flag="-f", dest="wordlist")
    parser.add_argument("-o",       dest="output",   default="found_params.json", help="JSON output file")
    parser.add_argument("--json",   dest="json_data", action="store_true", help="Send POST data as JSON")
    parser.add_argument("--header", dest="headers",  nargs="*", help="Extra headers (key:value)")
    args = parser.parse_args()

    extra_headers: dict = {}
    if args.headers:
        for h in args.headers:
            k, _, v = h.partition(":")
            extra_headers[k.strip()] = v.strip()

    urls = []
    if args.url:
        urls.append(args.url)
    if args.url_file:
        with open(args.url_file) as f:
            urls += [line.strip() for line in f if line.strip()]

    if not urls:
        parser.error("Provide -u URL or --urls file.")

    wl = WL.resolve(args.wordlist, "params") if args.wordlist else WL.params()
    results = {}
    for url in urls:
        results[url] = mine(url, wl, extra_headers, args.json_data)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=4)
    print(f"{info} Results saved to {args.output}")


if __name__ == "__main__":
    main()
