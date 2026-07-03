#!/usr/bin/python3
"""
Finding Tracker — central triage database for Catch403.

Every scan module can push findings here. Triage them (confirm / reject /
annotate), track remediation, and feed into report_generator.py.

DB: ~/.catch403/findings.db

Usage:
  ../.venv/bin/python3 modules/finding_tracker.py --list
  ../.venv/bin/python3 modules/finding_tracker.py --list --severity critical,high
  ../.venv/bin/python3 modules/finding_tracker.py --confirm 3 --note "Verified in prod"
  ../.venv/bin/python3 modules/finding_tracker.py --reject 7 --note "Only on staging"
  ../.venv/bin/python3 modules/finding_tracker.py --wontfix 4
  ../.venv/bin/python3 modules/finding_tracker.py --note 2 "CVSS 9.1, needs fast patch"
  ../.venv/bin/python3 modules/finding_tracker.py --import findings.json
  ../.venv/bin/python3 modules/finding_tracker.py --export report.json
  ../.venv/bin/python3 modules/finding_tracker.py --stats
"""
import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

from core.colors import bold, end, good, bad, info, run

DB_PATH = os.path.expanduser("~/.catch403/findings.db")

# Status values
PENDING       = "pending"
CONFIRMED     = "confirmed"
FALSE_POSITIVE = "false_positive"
WONT_FIX      = "wont_fix"
FIXED         = "fixed"

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_COLOUR = {
    "critical": "\033[91m",
    "high":     "\033[33m",
    "medium":   "\033[93m",
    "low":      "\033[94m",
    "info":     "\033[37m",
}
_STATUS_COLOUR = {
    PENDING:        "\033[37m",
    CONFIRMED:      "\033[91m",
    FALSE_POSITIVE: "\033[90m",
    WONT_FIX:       "\033[90m",
    FIXED:          "\033[92m",
}
RESET = "\033[0m"


class FindingTracker:
    def __init__(self, db_path: str = DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db = db_path
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._db)
        c.row_factory = sqlite3.Row
        return c

    def _init(self):
        with self._conn() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    added_at        TEXT NOT NULL,
                    source_module   TEXT NOT NULL DEFAULT '',
                    name            TEXT NOT NULL,
                    severity        TEXT NOT NULL DEFAULT 'info',
                    detail          TEXT NOT NULL DEFAULT '',
                    url             TEXT NOT NULL DEFAULT '',
                    param           TEXT NOT NULL DEFAULT '',
                    payload         TEXT NOT NULL DEFAULT '',
                    http_request    TEXT NOT NULL DEFAULT '',
                    curl            TEXT NOT NULL DEFAULT '',
                    raw             TEXT NOT NULL DEFAULT '{}',
                    status          TEXT NOT NULL DEFAULT 'pending',
                    triage_at       TEXT,
                    notes           TEXT NOT NULL DEFAULT '',
                    tags            TEXT NOT NULL DEFAULT ''
                )
            """)

    # ── write ──────────────────────────────────────────────────────────────

    def add(self, finding: dict, source_module: str = "") -> int:
        """Insert a finding dict (standard list[dict] format). Returns new id."""
        # Skip internal meta findings
        if finding.get("severity") in ("meta",):
            return -1
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            cur = c.execute("""
                INSERT INTO findings
                  (added_at, source_module, name, severity, detail, url, param,
                   payload, http_request, curl, raw, status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                now,
                source_module or finding.get("_source", ""),
                finding.get("name", ""),
                finding.get("severity", "info"),
                finding.get("detail", ""),
                finding.get("url", ""),
                finding.get("param", finding.get("parameter", "")),
                finding.get("payload", ""),
                finding.get("http_request", ""),
                finding.get("curl", finding.get("curl_command", "")),
                json.dumps(finding),
                PENDING,
            ))
            return cur.lastrowid

    def add_many(self, findings: list[dict], source_module: str = "") -> list[int]:
        return [self.add(f, source_module) for f in findings
                if f.get("severity") != "meta"]

    def update_status(self, finding_id: int, status: str,
                      notes: str = "") -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            cur = c.execute("""
                UPDATE findings
                   SET status = ?, triage_at = ?,
                       notes  = CASE
                         WHEN ? = '' THEN notes
                         WHEN notes = '' THEN ?
                         ELSE notes || char(10) || ?
                       END
                 WHERE id = ?
            """, (status, now, notes, notes, notes, finding_id))
            return cur.rowcount > 0

    def add_note(self, finding_id: int, note: str) -> bool:
        with self._conn() as c:
            cur = c.execute("""
                UPDATE findings
                   SET notes = CASE
                     WHEN notes = '' THEN ?
                     ELSE notes || char(10) || ?
                   END
                 WHERE id = ?
            """, (note, note, finding_id))
            return cur.rowcount > 0

    def add_tag(self, finding_id: int, tag: str) -> bool:
        with self._conn() as c:
            cur = c.execute("""
                UPDATE findings
                   SET tags = CASE
                     WHEN tags = '' THEN ?
                     WHEN instr(tags, ?) = 0 THEN tags || ',' || ?
                     ELSE tags
                   END
                 WHERE id = ?
            """, (tag, tag, tag, finding_id))
            return cur.rowcount > 0

    def delete(self, finding_id: int) -> bool:
        with self._conn() as c:
            cur = c.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
            return cur.rowcount > 0

    def clear(self, status: str = ""):
        with self._conn() as c:
            if status:
                c.execute("DELETE FROM findings WHERE status = ?", (status,))
            else:
                c.execute("DELETE FROM findings")

    # ── read ───────────────────────────────────────────────────────────────

    def get(self, finding_id: int) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM findings WHERE id = ?",
                            (finding_id,)).fetchone()
        return dict(row) if row else None

    def query(self, *,
              status: str | list[str] = "",
              severity: str | list[str] = "",
              source: str = "",
              url_like: str = "",
              tag: str = "",
              limit: int = 0) -> list[dict]:
        clauses, params = [], []
        def _in(field, val):
            if isinstance(val, str):
                val = [v.strip() for v in val.split(",") if v.strip()]
            if val:
                clauses.append(f"{field} IN ({','.join('?'*len(val))})")
                params.extend(val)
        _in("status",   status)
        _in("severity", severity)
        if source:
            clauses.append("source_module LIKE ?")
            params.append(f"%{source}%")
        if url_like:
            clauses.append("url LIKE ?")
            params.append(f"%{url_like}%")
        if tag:
            clauses.append("(',' || tags || ',') LIKE ?")
            params.append(f"%,{tag},%")
        sql = "SELECT * FROM findings"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY CASE severity"
        for k, v in _SEV_ORDER.items():
            sql += f" WHEN '{k}' THEN {v}"
        sql += " ELSE 9 END, added_at DESC"
        if limit:
            sql += f" LIMIT {limit}"
        with self._conn() as c:
            rows = c.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        with self._conn() as c:
            rows = c.execute("""
                SELECT severity, status, COUNT(*) as cnt
                  FROM findings
                 GROUP BY severity, status
            """).fetchall()
        result: dict = {"by_severity": {}, "by_status": {}, "total": 0}
        for row in rows:
            sev, status, cnt = row["severity"], row["status"], row["cnt"]
            result["by_severity"].setdefault(sev, 0)
            result["by_severity"][sev] += cnt
            result["by_status"].setdefault(status, 0)
            result["by_status"][status] += cnt
            result["total"] += cnt
        return result

    # ── export / import ────────────────────────────────────────────────────

    def export_json(self, path: str, status: str = "") -> int:
        rows = self.query(status=status)
        with open(path, "w") as fh:
            json.dump(rows, fh, indent=2)
        return len(rows)

    def import_json(self, path: str, source_module: str = "import") -> int:
        with open(path) as fh:
            findings = json.load(fh)
        if isinstance(findings, dict):
            # Flat finding dict
            findings = [findings]
        ids = self.add_many(findings, source_module)
        return len([i for i in ids if i > 0])


# ── CLI helpers ────────────────────────────────────────────────────────────

def _sev_prefix(sev: str) -> str:
    c = _SEV_COLOUR.get(sev, "")
    return f"{c}{sev.upper():<8}{RESET}"


def _status_label(status: str) -> str:
    c = _STATUS_COLOUR.get(status, "")
    return f"{c}{status:<14}{RESET}"


def _print_finding(f: dict, verbose: bool = False):
    sev = _sev_prefix(f["severity"])
    sta = _status_label(f["status"])
    print(f"  [{f['id']:>3}] {sev} {sta} {bold}{f['name']}{end}")
    if f.get("url"):
        print(f"        URL    : {f['url']}")
    if f.get("detail") and verbose:
        for line in f["detail"].splitlines()[:3]:
            print(f"        Detail : {line}")
    if f.get("notes"):
        for line in f["notes"].splitlines():
            print(f"        Note   : {line}")
    if f.get("tags"):
        print(f"        Tags   : {f['tags']}")


def main():
    parser = argparse.ArgumentParser(description="Catch403 Finding Tracker")
    parser.add_argument("--list",     action="store_true", help="List findings")
    parser.add_argument("--stats",    action="store_true", help="Show stats")
    parser.add_argument("--get",      type=int, metavar="ID", help="Show full finding")
    parser.add_argument("--confirm",  type=int, metavar="ID")
    parser.add_argument("--reject",   type=int, metavar="ID", dest="fp")
    parser.add_argument("--wontfix",  type=int, metavar="ID")
    parser.add_argument("--fixed",    type=int, metavar="ID")
    parser.add_argument("--note",     nargs=2,  metavar=("ID", "TEXT"))
    parser.add_argument("--tag",      nargs=2,  metavar=("ID", "TAG"))
    parser.add_argument("--delete",   type=int, metavar="ID")
    parser.add_argument("--import",   dest="imp", metavar="FILE")
    parser.add_argument("--export",   metavar="FILE")
    parser.add_argument("--clear",    action="store_true")
    parser.add_argument("--severity", default="", help="Filter: critical,high,…")
    parser.add_argument("--status",   default="", help="Filter: pending,confirmed,…")
    parser.add_argument("--source",   default="", help="Filter by source module")
    parser.add_argument("--url",      default="", help="Filter by URL substring")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    db = FindingTracker()

    if args.stats:
        s = db.stats()
        print(f"\n{bold}Finding Stats{end}  (total: {s['total']})\n")
        print(f"  {bold}By Severity:{end}")
        for sev in ("critical","high","medium","low","info"):
            n = s["by_severity"].get(sev, 0)
            if n:
                bar = "█" * min(n, 40)
                print(f"    {_sev_prefix(sev)} {bar} {n}")
        print(f"\n  {bold}By Status:{end}")
        for st, n in sorted(s["by_status"].items()):
            print(f"    {_status_label(st)} {n}")
        print()
        return

    if args.list:
        rows = db.query(severity=args.severity, status=args.status,
                        source=args.source, url_like=args.url)
        if not rows:
            print(f"{info} No findings match filter")
            return
        print(f"\n  {'ID':>4}  {'SEV':<8} {'STATUS':<14} Name")
        print("  " + "─" * 72)
        for f in rows:
            _print_finding(f, args.verbose)
        print(f"\n  {len(rows)} finding(s)\n")
        return

    if args.get:
        f = db.get(args.get)
        if not f:
            print(f"{bad} Finding {args.get} not found")
            sys.exit(1)
        print(json.dumps(f, indent=2))
        return

    if args.confirm:
        note = ""
        db.update_status(args.confirm, CONFIRMED, note)
        print(f"{good} #{args.confirm} → confirmed")
        return

    if args.fp:
        db.update_status(args.fp, FALSE_POSITIVE)
        print(f"{info} #{args.fp} → false_positive")
        return

    if args.wontfix:
        db.update_status(args.wontfix, WONT_FIX)
        print(f"{info} #{args.wontfix} → wont_fix")
        return

    if args.fixed:
        db.update_status(args.fixed, FIXED)
        print(f"{good} #{args.fixed} → fixed")
        return

    if args.note:
        fid, text = int(args.note[0]), args.note[1]
        db.add_note(fid, text)
        print(f"{good} Note added to #{fid}")
        return

    if args.tag:
        fid, tag = int(args.tag[0]), args.tag[1]
        db.add_tag(fid, tag)
        print(f"{good} Tag '{tag}' added to #{fid}")
        return

    if args.delete:
        db.delete(args.delete)
        print(f"{info} #{args.delete} deleted")
        return

    if args.imp:
        n = db.import_json(args.imp)
        print(f"{good} Imported {n} finding(s) from {args.imp}")
        return

    if args.export:
        n = db.export_json(args.export, status=args.status)
        print(f"{good} Exported {n} finding(s) to {args.export}")
        return

    if args.clear:
        db.clear(args.status)
        print(f"{good} Findings cleared")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
