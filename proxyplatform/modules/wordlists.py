#!/usr/bin/python3
"""
Wordlists — curated SecLists wordlists bundled with Catch403.

All files live in wordlists/ at the repo root. Each list is small and focused —
no files exceed 10,000 lines. Sources: danielmiessler/SecLists (MIT).

Usage:
  from modules.wordlists import WL
  paths = WL.paths()        # content discovery
  params = WL.params()      # param miner
  xss = WL.xss()            # XSS payloads
  sqli = WL.sqli()          # SQLi payloads
"""
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_WORDLISTS = os.path.abspath(os.path.join(_HERE, "..", "..", "wordlists"))


def _load(filename: str) -> list[str]:
    path = os.path.join(_WORDLISTS, filename)
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return [line.strip() for line in fh
                if line.strip() and not line.startswith("#")]


class WL:
    """Namespace of wordlist loaders."""

    # ── discovery ──────────────────────────────────────────────────────────
    @staticmethod
    def paths() -> list[str]:
        """~4750 common web paths (SecLists common.txt + curated extras)."""
        return _load("seclists-paths.txt") or _load("paths.txt")

    @staticmethod
    def api() -> list[str]:
        """~295 API endpoint paths."""
        return _load("seclists-api.txt")

    @staticmethod
    def subdomains() -> list[str]:
        """Top 5000 subdomains."""
        return _load("seclists-subdomains.txt") or _load("subdomains.txt")

    # ── auth ───────────────────────────────────────────────────────────────
    @staticmethod
    def usernames() -> list[str]:
        """Short high-signal username list."""
        return _load("seclists-usernames.txt") or _load("usernames.txt")

    @staticmethod
    def passwords() -> list[str]:
        """Top 25 common passwords (default cred testing, not cracking)."""
        return _load("seclists-passwords.txt") or _load("passwords.txt")

    # ── fuzzing payloads ───────────────────────────────────────────────────
    @staticmethod
    def xss() -> list[str]:
        """~113 XSS payloads (BruteLogic focused set)."""
        return _load("seclists-xss.txt")

    @staticmethod
    def sqli() -> list[str]:
        """~268 generic SQL injection payloads."""
        return _load("seclists-sqli.txt")

    @staticmethod
    def sqli_auth_bypass() -> list[str]:
        """~96 SQL auth bypass payloads."""
        return _load("seclists-sqli-auth.txt")

    @staticmethod
    def sqli_polyglots() -> list[str]:
        """Multi-DBMS polyglot SQLi payloads."""
        return _load("seclists-sqli-polyglots.txt")

    @staticmethod
    def lfi() -> list[str]:
        """~930 LFI/path traversal payloads."""
        return _load("seclists-lfi.txt")

    @staticmethod
    def xxe() -> list[str]:
        """~51 XXE fuzzing payloads."""
        return _load("seclists-xxe.txt")

    @staticmethod
    def ssti() -> list[str]:
        """Template engine expression payloads."""
        return _load("seclists-ssti.txt")

    @staticmethod
    def cmdi() -> list[str]:
        """~3000 command injection payloads (commix-curated)."""
        return _load("seclists-cmdi.txt")

    @staticmethod
    def ldap() -> list[str]:
        """~26 LDAP fuzzing payloads."""
        return _load("seclists-ldap.txt")

    # ── params ─────────────────────────────────────────────────────────────
    @staticmethod
    def params() -> list[str]:
        """Common HTTP parameter names for param miner."""
        return _load("params.txt")

    @staticmethod
    def all_names() -> dict[str, str]:
        """Map of list name → filename for discovery and help text."""
        return {
            "paths":          "seclists-paths.txt (4750)",
            "api":            "seclists-api.txt (295)",
            "subdomains":     "seclists-subdomains.txt (5000)",
            "usernames":      "seclists-usernames.txt (17)",
            "passwords":      "seclists-passwords.txt (25)",
            "xss":            "seclists-xss.txt (113)",
            "sqli":           "seclists-sqli.txt (268)",
            "sqli-auth":      "seclists-sqli-auth.txt (96)",
            "sqli-polyglots": "seclists-sqli-polyglots.txt",
            "lfi":            "seclists-lfi.txt (930)",
            "xxe":            "seclists-xxe.txt (51)",
            "ssti":           "seclists-ssti.txt (11)",
            "cmdi":           "seclists-cmdi.txt (3000)",
            "ldap":           "seclists-ldap.txt (26)",
            "params":         "params.txt (curated)",
        }


if __name__ == "__main__":
    print("Wordlists available:\n")
    for name, desc in WL.all_names().items():
        entries = len(_load(desc.split()[0]))
        status = "✓" if entries else "✗ missing"
        print(f"  {name:<20} {desc:<40} {status}")
