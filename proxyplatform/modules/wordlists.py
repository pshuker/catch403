#!/usr/bin/python3
"""
Wordlists — registry and loader for all Catch403 wordlists.

Acts as a central database of available lists.  Every module that accepts -w
resolves the argument through here: you can pass either a registry name or a
plain file path.

CLI:
  ../.venv/bin/python3 modules/wordlists.py --list
  ../.venv/bin/python3 modules/wordlists.py --list paths
  ../.venv/bin/python3 modules/wordlists.py --preview xss

Python API:
  from modules.wordlists import WL
  WL.resolve("seclists-paths")   # by registry name
  WL.resolve("/path/to/my.txt")  # by file path
  WL.resolve("xss", "xss")      # name OR default for category
  WL.list("paths")               # all names in a category
  WL.default("paths")            # → "seclists-paths"
"""
import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_WORDLISTS_DIR = os.path.abspath(os.path.join(_HERE, "..", "..", "wordlists"))

# ── registry ───────────────────────────────────────────────────────────────
# Each entry: name → (filename, category, description)
REGISTRY: dict[str, tuple[str, str, str]] = {
    # ── path / content discovery ──────────────────────────────────────────
    "paths-small":      ("paths.txt",               "paths",     "~200 curated high-value paths"),
    "seclists-paths":   ("seclists-paths.txt",       "paths",     "4750 paths — SecLists common.txt"),
    "seclists-api":     ("seclists-api.txt",         "paths",     "295 API endpoint paths"),

    # ── subdomains ────────────────────────────────────────────────────────
    "subdomains-small": ("subdomains.txt",           "subdomains","~90 curated common subdomains"),
    "seclists-subdomains":("seclists-subdomains.txt","subdomains","Top 5000 subdomains"),

    # ── usernames ─────────────────────────────────────────────────────────
    "usernames-small":  ("usernames.txt",            "usernames", "~60 curated service usernames"),
    "seclists-usernames":("seclists-usernames.txt",  "usernames", "17 top usernames — SecLists shortlist"),

    # ── passwords ─────────────────────────────────────────────────────────
    "passwords-small":  ("passwords.txt",            "passwords", "~50 curated default/weak passwords"),
    "seclists-passwords":("seclists-passwords.txt",  "passwords", "25 top passwords — SecLists shortlist"),

    # ── parameters ────────────────────────────────────────────────────────
    "params":           ("params.txt",               "params",    "~100 common HTTP parameter names"),

    # ── injection payloads ────────────────────────────────────────────────
    "xss":              ("seclists-xss.txt",         "xss",       "113 XSS payloads — BruteLogic focused"),
    "sqli":             ("seclists-sqli.txt",        "sqli",      "268 generic SQLi payloads"),
    "sqli-auth":        ("seclists-sqli-auth.txt",   "sqli",      "96 SQLi auth bypass payloads"),
    "sqli-polyglots":   ("seclists-sqli-polyglots.txt","sqli",    "Multi-DBMS polyglot payloads"),
    "lfi":              ("seclists-lfi.txt",         "lfi",       "930 LFI / path traversal payloads"),
    "xxe":              ("seclists-xxe.txt",         "xxe",       "51 XXE fuzzing payloads"),
    "ssti":             ("seclists-ssti.txt",        "ssti",      "11 template engine expression payloads"),
    "cmdi":             ("seclists-cmdi.txt",        "cmdi",      "3000 command injection payloads"),
    "ldap":             ("seclists-ldap.txt",        "ldap",      "26 LDAP fuzzing payloads"),
}

# Default list per category — used when no -w given
_DEFAULTS: dict[str, str] = {
    "paths":      "seclists-paths",
    "subdomains": "seclists-subdomains",
    "usernames":  "seclists-usernames",
    "passwords":  "seclists-passwords",
    "params":     "params",
    "xss":        "xss",
    "sqli":       "sqli",
    "lfi":        "lfi",
    "xxe":        "xxe",
    "ssti":       "ssti",
    "cmdi":       "cmdi",
    "ldap":       "ldap",
}


def _load_file(path: str) -> list[str]:
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return [line.strip() for line in fh
                if line.strip() and not line.startswith("#")]


class WL:
    """Central wordlist registry — resolve names or paths to list[str]."""

    @staticmethod
    def resolve(name_or_path: str, category: str = "") -> list[str]:
        """
        Load a wordlist by registry name or file path.

        If name_or_path is a registry key → load from wordlists/.
        If name_or_path is a file path that exists → load directly.
        If name_or_path is empty and category is set → load the category default.
        """
        if not name_or_path and category:
            name_or_path = _DEFAULTS.get(category, "")
        if not name_or_path:
            return []

        # Registry lookup first
        if name_or_path in REGISTRY:
            filename, _, _ = REGISTRY[name_or_path]
            return _load_file(os.path.join(_WORDLISTS_DIR, filename))

        # Direct file path
        if os.path.isfile(name_or_path):
            return _load_file(name_or_path)

        # Fuzzy match: try prefix
        matches = [k for k in REGISTRY if k.startswith(name_or_path)]
        if len(matches) == 1:
            filename, _, _ = REGISTRY[matches[0]]
            return _load_file(os.path.join(_WORDLISTS_DIR, filename))

        return []

    @staticmethod
    def default(category: str) -> str:
        """Return the default registry name for a category."""
        return _DEFAULTS.get(category, "")

    @staticmethod
    def list(category: str = "") -> list[tuple[str, str, int]]:
        """
        Return [(name, description, entry_count)] for all lists,
        optionally filtered by category.
        """
        rows = []
        for name, (filename, cat, desc) in REGISTRY.items():
            if category and cat != category:
                continue
            path = os.path.join(_WORDLISTS_DIR, filename)
            count = len(_load_file(path)) if os.path.isfile(path) else 0
            rows.append((name, cat, desc, count))
        return rows

    @staticmethod
    def categories() -> list[str]:
        return sorted(set(cat for _, cat, _ in REGISTRY.values()))

    # ── convenience loaders (backward-compatible) ──────────────────────────
    @staticmethod
    def paths()      -> list[str]: return WL.resolve("", "paths")
    @staticmethod
    def api()        -> list[str]: return WL.resolve("seclists-api")
    @staticmethod
    def subdomains() -> list[str]: return WL.resolve("", "subdomains")
    @staticmethod
    def usernames()  -> list[str]: return WL.resolve("", "usernames")
    @staticmethod
    def passwords()  -> list[str]: return WL.resolve("", "passwords")
    @staticmethod
    def params()     -> list[str]: return WL.resolve("params")
    @staticmethod
    def xss()        -> list[str]: return WL.resolve("xss")
    @staticmethod
    def sqli()       -> list[str]: return WL.resolve("sqli")
    @staticmethod
    def sqli_auth_bypass() -> list[str]: return WL.resolve("sqli-auth")
    @staticmethod
    def sqli_polyglots()   -> list[str]: return WL.resolve("sqli-polyglots")
    @staticmethod
    def lfi()        -> list[str]: return WL.resolve("lfi")
    @staticmethod
    def xxe()        -> list[str]: return WL.resolve("xxe")
    @staticmethod
    def ssti()       -> list[str]: return WL.resolve("ssti")
    @staticmethod
    def cmdi()       -> list[str]: return WL.resolve("cmdi")
    @staticmethod
    def ldap()       -> list[str]: return WL.resolve("ldap")


# ── shared argparse helper ────────────────────────────────────────────────

def add_wordlist_arg(parser: argparse.ArgumentParser, category: str,
                     flag: str = "-w", dest: str = "wordlist",
                     help_suffix: str = "") -> None:
    """
    Add a -w / --wordlist argument to a module's argparse parser.

    The default shown is the registry default for the category.
    The value passed at runtime is resolved via WL.resolve(value, category).
    """
    default_name = _DEFAULTS.get(category, "")
    default_count = len(WL.resolve(default_name)) if default_name else 0
    parser.add_argument(
        flag, "--wordlist",
        dest=dest, default="",
        metavar="NAME|PATH",
        help=(
            f"Wordlist registry name or file path "
            f"(default: {default_name!r}, {default_count} entries). "
            f"Run `python3 modules/wordlists.py --list {category}` to see options."
            + (f" {help_suffix}" if help_suffix else "")
        ),
    )


# ── CLI ────────────────────────────────────────────────────────────────────

def _print_table(rows: list[tuple]) -> None:
    if not rows:
        print("  (none)")
        return
    for name, cat, desc, count in rows:
        status = f"{count:>5} entries" if count else "  MISSING "
        print(f"  {name:<24} {cat:<12} {status}   {desc}")


def main():
    parser = argparse.ArgumentParser(description="Catch403 Wordlist Registry")
    parser.add_argument("--list", nargs="?", const="", metavar="CATEGORY",
                        help="List all wordlists, or filter by category")
    parser.add_argument("--preview", metavar="NAME",
                        help="Print first 10 lines of a wordlist")
    parser.add_argument("--categories", action="store_true",
                        help="List available categories")
    args = parser.parse_args()

    if args.categories:
        print("Categories:")
        for cat in WL.categories():
            default = _DEFAULTS.get(cat, "")
            print(f"  {cat:<14} default: {default}")
        return

    if args.list is not None:
        cat = args.list.strip()
        rows = WL.list(cat)
        header = f"Wordlists{' — ' + cat if cat else ''}:"
        print(f"\n{header}")
        print(f"  {'Name':<24} {'Category':<12} {'Entries':>12}   Description")
        print("  " + "-" * 72)
        _print_table(rows)
        print(f"\n  Use:  -w <NAME>   or   -w /path/to/custom.txt\n")
        return

    if args.preview:
        lines = WL.resolve(args.preview)
        if not lines:
            print(f"Not found: {args.preview!r}")
            sys.exit(1)
        print(f"# {args.preview} — first 10 of {len(lines)} entries")
        for line in lines[:10]:
            print(f"  {line}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
