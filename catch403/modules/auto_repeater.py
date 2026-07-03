#!/usr/bin/python3
"""
Auto Repeater — automatically resend HTTP requests that match defined rules,
with optional header/param modifications.
Inspired by the Burp Auto Repeater extension.

Rules define: match conditions (host, path, status, method, body regex)
              + modifications (add/replace/remove headers, cookies, params)
              + comparison (diff original vs modified response)

The Auto Repeater runs as a background thread, pulling from a shared queue
populated by the intercepting proxy.

Usage:
  from modules.auto_repeater import AutoRepeater, Rule
  ar = AutoRepeater()
  ar.add_rule(Rule(
      name="Remove auth header",
      match_host="target.com",
      modifications={"remove_headers": ["Authorization"]},
  ))
  ar.process(method, url, headers, body)

  ../.venv/bin/python3 modules/auto_repeater.py --rules rules.json --demo
"""
import argparse
import difflib
import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

import requests
import urllib3

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab

urllib3.disable_warnings()

UA = "Mozilla/5.0 (compatible; Catch403/1.0)"
TIMEOUT = 10


@dataclass
class Rule:
    name: str = "Rule"

    # Match conditions (all must match)
    match_host:     str | None = None   # regex
    match_path:     str | None = None   # regex
    match_method:   str | None = None   # GET, POST, ...
    match_status:   int | None = None   # exact status code to re-send on
    match_body_re:  str | None = None   # regex on request body

    # Modifications to apply to the repeated request
    add_headers:    dict = field(default_factory=dict)   # {name: value}
    remove_headers: list = field(default_factory=list)   # [name, ...]
    replace_headers:dict = field(default_factory=dict)   # {name: new_value}
    add_params:     dict = field(default_factory=dict)   # query params
    replace_body:   str | None = None   # replace entire body

    # Post-send behaviour
    compare: bool = True   # diff original vs modified response
    log:     bool = True   # add result to traffic log

    def matches(self, method: str, url: str, headers: dict,
                body: str, status: int | None = None) -> bool:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host   = parsed.netloc

        if self.match_host and not re.search(self.match_host, host, re.I):
            return False
        if self.match_path and not re.search(self.match_path, parsed.path, re.I):
            return False
        if self.match_method and method.upper() != self.match_method.upper():
            return False
        if self.match_status is not None and status != self.match_status:
            return False
        if self.match_body_re and not re.search(self.match_body_re, body or "", re.I):
            return False
        return True

    def apply(self, headers: dict, body: str | None,
              url: str) -> tuple[dict, str | None, str]:
        from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
        h = dict(headers)

        for k in self.remove_headers:
            h.pop(k, None)
            # case-insensitive removal
            for existing in list(h.keys()):
                if existing.lower() == k.lower():
                    del h[existing]

        h.update(self.add_headers)
        h.update(self.replace_headers)

        if self.replace_body is not None:
            body = self.replace_body

        if self.add_params:
            parsed = urlparse(url)
            params = dict(parse_qsl(parsed.query))
            params.update(self.add_params)
            new_query = urlencode(params)
            url = urlunparse(parsed._replace(query=new_query))

        return h, body, url

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "match_host": self.match_host,
            "match_path": self.match_path,
            "match_method": self.match_method,
            "match_status": self.match_status,
            "match_body_re": self.match_body_re,
            "add_headers": self.add_headers,
            "remove_headers": self.remove_headers,
            "replace_headers": self.replace_headers,
            "add_params": self.add_params,
            "replace_body": self.replace_body,
            "compare": self.compare,
            "log": self.log,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class RepeaterResult:
    def __init__(self, rule_name: str, original_url: str, method: str,
                 orig_status: int, orig_len: int,
                 mod_status: int, mod_len: int,
                 diff_lines: int, similarity: float,
                 mod_body: str):
        self.rule_name    = rule_name
        self.original_url = original_url
        self.method       = method
        self.orig_status  = orig_status
        self.orig_len     = orig_len
        self.mod_status   = mod_status
        self.mod_len      = mod_len
        self.diff_lines   = diff_lines
        self.similarity   = similarity
        self.mod_body     = mod_body

    def interesting(self) -> bool:
        """Flag if modified response differs significantly from original."""
        return (self.mod_status != self.orig_status or
                abs(self.mod_len - self.orig_len) > 50 or
                self.similarity < 0.90)


class AutoRepeater:
    def __init__(self):
        self.rules:   list[Rule]          = []
        self.results: list[RepeaterResult] = []
        self._lock    = threading.Lock()
        self.session  = requests.Session()
        self.session.headers["User-Agent"] = UA
        self.session.verify = False

    def add_rule(self, rule: Rule) -> None:
        with self._lock:
            self.rules.append(rule)

    def remove_rule(self, idx: int) -> None:
        with self._lock:
            self.rules.pop(idx)

    def _send(self, method: str, url: str, headers: dict,
              body: str | None) -> tuple[int, int, str]:
        try:
            r = self.session.request(method, url, headers=headers,
                                     data=body, timeout=TIMEOUT,
                                     allow_redirects=False)
            return r.status_code, len(r.content), r.text
        except Exception as e:
            return 0, 0, str(e)

    def process(self, method: str, url: str, headers: dict,
                body: str | None, orig_status: int = 200,
                orig_body: str = "") -> list[RepeaterResult]:
        """
        Check all rules against this request. For each matching rule,
        resend with modifications and compare responses.
        """
        results = []

        with self._lock:
            active_rules = list(self.rules)

        for rule in active_rules:
            if not rule.matches(method, url, headers, body or "", orig_status):
                continue

            # Apply modifications
            mod_headers, mod_body, mod_url = rule.apply(dict(headers), body, url)

            # Send modified request
            mod_status, mod_len, mod_body_text = self._send(method, mod_url, mod_headers, mod_body)

            # Compare
            orig_lines = orig_body.splitlines()
            mod_lines  = mod_body_text.splitlines()
            diff = list(difflib.unified_diff(orig_lines, mod_lines, lineterm=""))
            sim  = difflib.SequenceMatcher(None, orig_body, mod_body_text).ratio()

            res = RepeaterResult(
                rule_name=rule.name, original_url=url, method=method,
                orig_status=orig_status, orig_len=len(orig_body or ""),
                mod_status=mod_status, mod_len=mod_len,
                diff_lines=len(diff), similarity=round(sim, 3),
                mod_body=mod_body_text[:2000],
            )
            results.append(res)
            with self._lock:
                self.results.append(res)

            if res.interesting():
                sc_col = green if mod_status < 300 else (yellow if mod_status < 400 else red)
                print(f"  {bad} {bold}[{rule.name}]{end} "
                      f"{method} {url[:60]}  "
                      f"orig={orig_status}/{len(orig_body or '')}B  "
                      f"mod={sc_col}{mod_status}{end}/{mod_len}B  "
                      f"sim={sim:.0%}")

        return results

    def load_rules(self, path: str) -> int:
        with open(path) as f:
            data = json.load(f)
        for d in data:
            self.add_rule(Rule.from_dict(d))
        return len(data)

    def save_rules(self, path: str) -> None:
        with self._lock:
            data = [r.to_dict() for r in self.rules]
        with open(path, "w") as f:
            json.dump(data, f, indent=2)


# ── Preset rules ───────────────────────────────────────────────────────────

PRESET_RULES = [
    Rule(name="Remove Authorization header",
         remove_headers=["Authorization"],
         compare=True),
    Rule(name="Remove Cookie header",
         remove_headers=["Cookie"],
         compare=True),
    Rule(name="Downgrade to HTTP",
         match_path=None,
         add_headers={"X-Forwarded-Proto": "http"},
         compare=True),
    Rule(name="Add internal IP header",
         add_headers={"X-Forwarded-For": "127.0.0.1",
                      "X-Real-IP": "127.0.0.1"},
         compare=True),
    Rule(name="Add low-priv cookie (anon)",
         replace_headers={"Cookie": "session=anonymous; role=guest"},
         compare=True),
]


def main():
    parser = argparse.ArgumentParser(description="Auto Repeater — rule-based request resender")
    parser.add_argument("--rules",  help="JSON file with rule definitions")
    parser.add_argument("--demo",   action="store_true",
                        help="Show preset rules that can be used")
    parser.add_argument("--export", help="Export preset rules to JSON file")
    args = parser.parse_args()

    if args.demo or not args.rules:
        print(f"\n{bold}{underline}Preset Auto Repeater Rules{end}\n")
        for i, rule in enumerate(PRESET_RULES):
            print(f"  [{i}] {bold}{rule.name}{end}")
            if rule.remove_headers:
                print(f"    {tab}Remove headers : {rule.remove_headers}")
            if rule.add_headers:
                print(f"    {tab}Add headers    : {rule.add_headers}")
            if rule.replace_headers:
                print(f"    {tab}Replace headers: {rule.replace_headers}")
        print()

    if args.export:
        data = [r.to_dict() for r in PRESET_RULES]
        with open(args.export, "w") as f:
            json.dump(data, f, indent=2)
        print(f"{good} Preset rules exported → {args.export}")

    if args.rules:
        ar = AutoRepeater()
        n = ar.load_rules(args.rules)
        print(f"{good} Loaded {n} rules from {args.rules}")
        print(f"{info} AutoRepeater is ready. Integrate with the intercepting proxy.")


if __name__ == "__main__":
    main()
