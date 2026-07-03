"""
auth_gate.py — one-time authorisation acknowledgement + per-run preflight.

preflight(module, url) is called at the top of every active module's main().
It does three things, none of which limit capability:
  1. First-run authorisation gate (one-time, never shown again after acceptance)
  2. Audit log entry (~/.catch403/audit.log)
  3. Scope check — only if scope rules are defined; empty scope = no restriction
"""
import getpass
import json
import os
import sys

from core import audit

_CONFIG_DIR = os.path.expanduser("~/.catch403")
_AUTH_FILE  = os.path.join(_CONFIG_DIR, "authorised.json")

_BANNER = """\
╔══════════════════════════════════════════════════════════════════╗
║              CATCH403 — AUTHORISED USE ONLY                     ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  This tool is for use ONLY against systems you own or have      ║
║  EXPLICIT WRITTEN AUTHORISATION to test.                        ║
║                                                                  ║
║  Unauthorised use is illegal under the Computer Fraud and       ║
║  Abuse Act (US), Computer Misuse Act (UK), and equivalent       ║
║  legislation worldwide.                                          ║
║                                                                  ║
║  This prompt appears once and never again.                      ║
╚══════════════════════════════════════════════════════════════════╝
"""


# ── authorisation gate ────────────────────────────────────────────────────

def _is_authorised() -> bool:
    try:
        with open(_AUTH_FILE) as fh:
            return json.load(fh).get("accepted", False)
    except Exception:
        return False


def _write_authorised() -> None:
    from datetime import datetime, timezone
    os.makedirs(_CONFIG_DIR, exist_ok=True)
    with open(_AUTH_FILE, "w") as fh:
        json.dump({
            "accepted":    True,
            "accepted_at": datetime.now(timezone.utc).isoformat(),
            "user":        getpass.getuser(),
        }, fh, indent=2)
    os.chmod(_AUTH_FILE, 0o600)


def require_authorisation() -> None:
    """Show one-time legal acknowledgement. No-op after first acceptance."""
    if _is_authorised():
        return
    print(_BANNER)
    print("Type  I ACCEPT  to confirm you will only use Catch403 against systems")
    print("you own or have explicit written permission to test.\n")
    try:
        response = input("→ ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")
        sys.exit(1)
    if response != "I ACCEPT":
        print("Authorisation not confirmed. Exiting.")
        sys.exit(1)
    _write_authorised()
    print("\n✓ Confirmed — this prompt will not appear again.\n")


# ── scope check ───────────────────────────────────────────────────────────

def _scope_check(url: str) -> None:
    """
    If scope rules exist, enforce them. Empty scope = everything allowed.
    Exits with a clear message if the host is not in scope.
    """
    try:
        from modules.scope import get_scope
        scope = get_scope()
        if not scope.list_rules():
            return          # no rules defined — no restriction
        if scope.is_in_scope(url):
            return
        from urllib.parse import urlparse
        host = urlparse(url).netloc or url
        print(f"\n  [!] OUT OF SCOPE: {host}")
        print(f"      Add it first:  python3 modules/scope.py add {host}")
        print(f"      Or check:      python3 modules/scope.py list\n")
        sys.exit(1)
    except ImportError:
        pass    # scope module unavailable — don't block


# ── preflight (call this from every active module's main()) ───────────────

def preflight(module_name: str, target_url: str, *, active: bool = True) -> None:
    """
    Single call that handles the full startup sequence:
      - One-time authorisation acknowledgement
      - Audit log entry
      - Scope enforcement (active modules only; skipped when no rules defined)

    Usage in module main():
        from core.auth_gate import preflight
        preflight("ssrf_scanner", args.url)
    """
    require_authorisation()
    audit.log_run(module_name, target_url)
    if active:
        _scope_check(target_url)
