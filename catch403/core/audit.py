"""
audit.py — append-only run log for accountability.

Every module run is recorded to ~/.catch403/audit.log as a JSON line:
  {"ts": "2026-07-03T14:22:01Z", "module": "ssrf_scanner", "target": "https://target.com", "user": "pedro"}

Standard professional-testing practice: you can show what you ran, against
what, and when — protects you as much as it protects the target.

CLI:
  python3 -m core.audit            # show last 20 entries
  python3 -m core.audit --tail 50
  python3 -m core.audit --grep target.com
  python3 -m core.audit --clear
"""
import getpass
import json
import os
import sys
from datetime import datetime, timezone

_AUDIT_LOG = os.path.expanduser("~/.catch403/audit.log")


def log_run(module: str, target: str) -> None:
    """Append one entry to the audit log. Silent on error — never blocks a scan."""
    try:
        os.makedirs(os.path.dirname(_AUDIT_LOG), exist_ok=True)
        entry = {
            "ts":     datetime.now(timezone.utc).isoformat(),
            "module": module,
            "target": target,
            "user":   getpass.getuser(),
        }
        with open(_AUDIT_LOG, "a") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def tail(n: int = 20) -> list[dict]:
    """Return the last n log entries."""
    try:
        with open(_AUDIT_LOG) as fh:
            lines = fh.readlines()
        entries = []
        for line in lines[-n:]:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return entries
    except FileNotFoundError:
        return []


def grep(pattern: str) -> list[dict]:
    """Return all entries whose target or module contains pattern."""
    pattern = pattern.lower()
    return [e for e in tail(10000)
            if pattern in e.get("target", "").lower()
            or pattern in e.get("module", "").lower()]


def clear() -> int:
    """Truncate the audit log. Returns number of entries cleared."""
    entries = tail(10000)
    try:
        open(_AUDIT_LOG, "w").close()
    except Exception:
        pass
    return len(entries)


# ── CLI ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Catch403 Audit Log")
    parser.add_argument("--tail",  type=int, default=20, metavar="N")
    parser.add_argument("--grep",  default="", metavar="PATTERN")
    parser.add_argument("--clear", action="store_true")
    args = parser.parse_args()

    if args.clear:
        n = clear()
        print(f"Audit log cleared ({n} entries removed)")
        sys.exit(0)

    entries = grep(args.grep) if args.grep else tail(args.tail)

    if not entries:
        print("No audit log entries found.")
        sys.exit(0)

    print(f"\n{'TS':<28} {'MODULE':<22} {'USER':<12} TARGET")
    print("─" * 100)
    for e in entries:
        ts     = e.get("ts", "")[:19].replace("T", " ")
        module = e.get("module", "")[:20]
        user   = e.get("user", "")[:10]
        target = e.get("target", "")[:55]
        print(f"{ts:<28} {module:<22} {user:<12} {target}")
    print()
