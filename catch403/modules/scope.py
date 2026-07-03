#!/usr/bin/python3
"""
Scope Manager — define in-scope targets used by all other modules.

Rules can be plain hostnames, URL prefixes, or Python regexes.
Two rule types: include and exclude. Exclusions take priority.
Empty scope = everything in scope.

Usage:
  from modules.scope import is_in_scope, get_scope
  scope = get_scope()
  scope.add("target.com")              # include hostname
  scope.add("https://target.com/api")  # include URL prefix
  scope.add(r".*\.staging\..*", "exclude")
  is_in_scope("https://target.com/login")  # -> True
"""
import json
import os
import re
import argparse
from urllib.parse import urlparse

from core.colors import bold, underline, end, green, red, yellow, good, bad, info, run, tab

SCOPE_FILE = os.path.expanduser("~/.catch403/scope.json")


class Scope:
    def __init__(self, path: str = SCOPE_FILE):
        self.path = path
        self.rules: list[dict] = []
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    self.rules = json.load(f)
            except Exception:
                self.rules = []

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self.rules, f, indent=2)

    def add(self, pattern: str, rule_type: str = "include") -> None:
        rule_type = rule_type.lower()
        if rule_type not in ("include", "exclude"):
            raise ValueError("rule_type must be 'include' or 'exclude'")
        self.rules.append({"pattern": pattern, "type": rule_type})
        self.save()

    def remove(self, idx: int) -> None:
        self.rules.pop(idx)
        self.save()

    def clear(self) -> None:
        self.rules = []
        self.save()

    def _matches(self, pattern: str, url: str, host: str) -> bool:
        try:
            return bool(re.search(pattern, url, re.IGNORECASE) or
                        re.search(pattern, host, re.IGNORECASE))
        except re.error:
            return (url.startswith(pattern) or
                    host == pattern or
                    host.endswith("." + pattern))

    def is_in_scope(self, url: str) -> bool:
        if not self.rules:
            return True

        parsed = urlparse(url)
        host = parsed.netloc or url

        included = excluded = False
        for rule in self.rules:
            if self._matches(rule["pattern"], url, host):
                if rule["type"] == "include":
                    included = True
                else:
                    excluded = True

        if excluded:
            return False
        return included

    def list_rules(self) -> list[dict]:
        return self.rules


_default_scope: Scope | None = None


def get_scope() -> Scope:
    global _default_scope
    if _default_scope is None:
        _default_scope = Scope()
    return _default_scope


def is_in_scope(url: str) -> bool:
    return get_scope().is_in_scope(url)


def _print_rules(scope: Scope) -> None:
    rules = scope.list_rules()
    if not rules:
        print(f"  {info} No scope rules defined — everything is in scope")
        return
    print(f"\n{bold}{underline}Scope Rules ({len(rules)}){end}\n")
    for i, r in enumerate(rules):
        col = green if r["type"] == "include" else red
        sym = "+" if r["type"] == "include" else "-"
        print(f"  [{i}] {col}{sym} {r['pattern']}{end}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Manage in-scope targets for catch403")
    sub = parser.add_subparsers(dest="cmd")

    add_p = sub.add_parser("add", help="Add a scope rule")
    add_p.add_argument("pattern", help="Hostname, URL prefix, or regex")
    add_p.add_argument("--exclude", action="store_true", help="Add as exclusion rule")

    rm_p = sub.add_parser("remove", help="Remove a rule by index")
    rm_p.add_argument("index", type=int)

    sub.add_parser("list",  help="List all rules")
    sub.add_parser("clear", help="Clear all rules")

    check_p = sub.add_parser("check", help="Check if a URL is in scope")
    check_p.add_argument("url")

    args = parser.parse_args()
    scope = get_scope()

    if args.cmd == "add":
        rtype = "exclude" if args.exclude else "include"
        scope.add(args.pattern, rtype)
        col = red if args.exclude else green
        print(f"{good} Added {col}{rtype}{end} rule: {args.pattern}")

    elif args.cmd == "remove":
        rules = scope.list_rules()
        if args.index >= len(rules):
            print(f"{bad} Index out of range (0-{len(rules)-1})")
            return
        removed = rules[args.index]
        scope.remove(args.index)
        print(f"{good} Removed [{args.index}] {removed['type']}: {removed['pattern']}")

    elif args.cmd == "list":
        _print_rules(scope)

    elif args.cmd == "clear":
        scope.clear()
        print(f"{good} Scope cleared")

    elif args.cmd == "check":
        result = scope.is_in_scope(args.url)
        col = green if result else red
        sym = good if result else bad
        print(f"{sym} {args.url}  →  {col}{'IN SCOPE' if result else 'OUT OF SCOPE'}{end}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
