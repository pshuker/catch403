#!/usr/bin/python3
"""
Logger++ — SQLite-backed HTTP traffic log with filtering and export.
Inspired by the Burp Logger++ extension.

Stores every proxied request/response with metadata. Supports:
  - Filter rules: host, path, status, method, content-type, body regex
  - Export: JSON, CSV, Burp XML
  - Called by the intercepting proxy to log traffic

Usage:
  from modules.logger_plus import TrafficLog
  log = TrafficLog()
  log.record(method, url, req_headers, req_body, status, resp_headers, resp_body)
  entries = log.query(host="target.com", status_min=200, status_max=299)
  log.export_json("traffic.json")

  ../.venv/bin/python3 modules/logger_plus.py --list
  ../.venv/bin/python3 modules/logger_plus.py --list --host target.com --status 200
  ../.venv/bin/python3 modules/logger_plus.py --export traffic.json
  ../.venv/bin/python3 modules/logger_plus.py --clear
"""
import argparse
import csv
import io
import json
import os
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
import base64
from contextlib import contextmanager
from datetime import datetime

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab

DB_PATH = os.path.expanduser("~/.proxyplatform/traffic.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   REAL    NOT NULL,
    method      TEXT    NOT NULL,
    url         TEXT    NOT NULL,
    host        TEXT    NOT NULL,
    path        TEXT    NOT NULL,
    req_headers TEXT,
    req_body    TEXT,
    status      INTEGER,
    resp_headers TEXT,
    resp_body   TEXT,
    content_type TEXT,
    resp_length INTEGER,
    duration_ms INTEGER,
    notes       TEXT
);
CREATE INDEX IF NOT EXISTS idx_host   ON traffic(host);
CREATE INDEX IF NOT EXISTS idx_status ON traffic(status);
CREATE INDEX IF NOT EXISTS idx_ts     ON traffic(timestamp);
"""


class TrafficLog:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    def record(self, method: str, url: str,
               req_headers: dict, req_body: str | bytes,
               status: int | None, resp_headers: dict, resp_body: str | bytes,
               duration_ms: int = 0, notes: str = "") -> int:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.netloc or url
        path = parsed.path or "/"

        if isinstance(req_body, bytes):
            req_body = req_body.decode(errors="replace")
        if isinstance(resp_body, bytes):
            resp_body = resp_body.decode(errors="replace")

        content_type = resp_headers.get("Content-Type", resp_headers.get("content-type", ""))

        with self._conn() as conn:
            cur = conn.execute("""
                INSERT INTO traffic
                  (timestamp, method, url, host, path, req_headers, req_body,
                   status, resp_headers, resp_body, content_type, resp_length, duration_ms, notes)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                time.time(), method.upper(), url, host, path,
                json.dumps(req_headers), req_body,
                status, json.dumps(resp_headers), resp_body,
                content_type.split(";")[0].strip(),
                len(resp_body or ""),
                duration_ms, notes,
            ))
            return cur.lastrowid

    def query(self, host: str | None = None, path_re: str | None = None,
              method: str | None = None, status_min: int | None = None,
              status_max: int | None = None, content_type: str | None = None,
              body_re: str | None = None, limit: int = 500) -> list[dict]:
        where, params = [], []

        if host:
            where.append("host LIKE ?"); params.append(f"%{host}%")
        if method:
            where.append("method = ?"); params.append(method.upper())
        if status_min is not None:
            where.append("status >= ?"); params.append(status_min)
        if status_max is not None:
            where.append("status <= ?"); params.append(status_max)
        if content_type:
            where.append("content_type LIKE ?"); params.append(f"%{content_type}%")

        sql = "SELECT * FROM traffic"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()

        results = [dict(r) for r in rows]

        # Post-filter: path regex and body regex (not easy in SQLite without FTS)
        if path_re:
            try:
                pat = re.compile(path_re, re.I)
                results = [r for r in results if pat.search(r["path"] or "")]
            except re.error:
                pass
        if body_re:
            try:
                pat = re.compile(body_re, re.I)
                results = [r for r in results
                           if pat.search(r["resp_body"] or "") or pat.search(r["req_body"] or "")]
            except re.error:
                pass

        return results

    def get(self, entry_id: int) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM traffic WHERE id=?", (entry_id,)).fetchone()
        return dict(row) if row else None

    def delete(self, entry_id: int) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM traffic WHERE id=?", (entry_id,))

    def clear(self) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM traffic")

    def count(self) -> int:
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM traffic").fetchone()[0]

    # ── export ─────────────────────────────────────────────────────────────

    def export_json(self, path: str, **filter_kwargs) -> int:
        rows = self.query(**filter_kwargs)
        with open(path, "w") as f:
            json.dump(rows, f, indent=2)
        return len(rows)

    def export_csv(self, path: str, **filter_kwargs) -> int:
        rows = self.query(**filter_kwargs)
        if not rows:
            return 0
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        return len(rows)

    def export_burp_xml(self, path: str, **filter_kwargs) -> int:
        rows = self.query(**filter_kwargs)
        items = ET.Element("items", burpVersion="2024", exportTime=datetime.now().isoformat())
        for r in rows:
            item = ET.SubElement(items, "item")
            ET.SubElement(item, "time").text     = datetime.fromtimestamp(r["timestamp"]).strftime("%c")
            ET.SubElement(item, "url").text      = r["url"]
            ET.SubElement(item, "host").text     = r["host"]
            ET.SubElement(item, "method").text   = r["method"]
            ET.SubElement(item, "path").text     = r["path"]
            ET.SubElement(item, "status").text   = str(r["status"] or "")
            # Burp XML uses base64-encoded request/response
            req_str = f"{r['method']} {r['path']} HTTP/1.1\r\n"
            for k, v in json.loads(r["req_headers"] or "{}").items():
                req_str += f"{k}: {v}\r\n"
            req_str += "\r\n" + (r["req_body"] or "")
            ET.SubElement(item, "request", encoding="base64").text = base64.b64encode(req_str.encode()).decode()

            resp_str = f"HTTP/1.1 {r['status']}\r\n"
            for k, v in json.loads(r["resp_headers"] or "{}").items():
                resp_str += f"{k}: {v}\r\n"
            resp_str += "\r\n" + (r["resp_body"] or "")
            ET.SubElement(item, "response", encoding="base64").text = base64.b64encode(resp_str.encode()).decode()

        tree = ET.ElementTree(items)
        ET.indent(tree, space="  ")
        tree.write(path, encoding="unicode", xml_declaration=True)
        return len(rows)


# ── CLI ────────────────────────────────────────────────────────────────────

def _status_colour(s: int | None) -> str:
    if s is None: return ""
    if s < 300:   return green
    if s < 400:   return yellow
    return red

def main():
    parser = argparse.ArgumentParser(description="Logger++ — view and export HTTP traffic")
    parser.add_argument("--list",    action="store_true", help="List log entries")
    parser.add_argument("--get",     type=int, metavar="ID", help="Show full entry by ID")
    parser.add_argument("--clear",   action="store_true", help="Clear all log entries")
    parser.add_argument("--count",   action="store_true", help="Show entry count")
    parser.add_argument("--export",  metavar="FILE",  help="Export to JSON (auto-detect by extension: .json, .csv, .xml)")

    # filters
    parser.add_argument("--host",    help="Filter by host (substring)")
    parser.add_argument("--method",  help="Filter by HTTP method")
    parser.add_argument("--status",  type=int, help="Filter by exact status code")
    parser.add_argument("--status-min", type=int, dest="status_min")
    parser.add_argument("--status-max", type=int, dest="status_max")
    parser.add_argument("--ct",      dest="content_type", help="Filter by content-type")
    parser.add_argument("--body",    dest="body_re", help="Regex on req/resp body")
    parser.add_argument("--path",    dest="path_re", help="Regex on URL path")
    parser.add_argument("--limit",   type=int, default=50, help="Max rows to show (default 50)")

    args = parser.parse_args()
    log = TrafficLog()

    filters = {}
    if args.host:        filters["host"]         = args.host
    if args.method:      filters["method"]        = args.method
    if args.status:      filters["status_min"]    = args.status; filters["status_max"] = args.status
    if args.status_min:  filters["status_min"]    = args.status_min
    if args.status_max:  filters["status_max"]    = args.status_max
    if args.content_type:filters["content_type"]  = args.content_type
    if args.body_re:     filters["body_re"]       = args.body_re
    if args.path_re:     filters["path_re"]       = args.path_re
    filters["limit"] = args.limit

    if args.count:
        print(f"{info} {log.count()} entries in log")

    elif args.clear:
        log.clear()
        print(f"{good} Log cleared")

    elif args.get:
        e = log.get(args.get)
        if not e:
            print(f"{bad} Entry {args.get} not found")
        else:
            print(f"\n{bold}#{e['id']} {e['method']} {e['url']}{end}")
            print(f"  Status: {_status_colour(e['status'])}{e['status']}{end}  |  {e['content_type']}  |  {e['resp_length']} bytes\n")
            print(f"{bold}Request Headers:{end}")
            for k, v in json.loads(e["req_headers"] or "{}").items():
                print(f"  {k}: {v}")
            if e["req_body"]:
                print(f"\n{bold}Request Body:{end}\n  {e['req_body'][:500]}")
            print(f"\n{bold}Response Headers:{end}")
            for k, v in json.loads(e["resp_headers"] or "{}").items():
                print(f"  {k}: {v}")
            if e["resp_body"]:
                print(f"\n{bold}Response Body (first 1000):{end}\n  {e['resp_body'][:1000]}")

    elif args.export:
        path = args.export
        if path.endswith(".csv"):
            n = log.export_csv(path, **filters)
        elif path.endswith(".xml"):
            n = log.export_burp_xml(path, **filters)
        else:
            n = log.export_json(path, **filters)
        print(f"{good} Exported {n} entries → {path}")

    else:
        entries = log.query(**filters)
        if not entries:
            print(f"{info} No entries found")
            return
        print(f"\n{bold}{'ID':<6} {'Time':<9} {'Method':<7} {'Status':<7} {'Host':<30} {'Path'}{end}")
        print("─" * 85)
        for e in entries:
            ts = datetime.fromtimestamp(e["timestamp"]).strftime("%H:%M:%S")
            sc = _status_colour(e["status"])
            s  = str(e["status"] or "?")
            host = (e["host"] or "")[:29]
            path = (e["path"] or "/")[:45]
            print(f"  {e['id']:<5} {ts:<9} {e['method']:<7} {sc}{s:<7}{end} {host:<30} {path}")
        print(f"\n  {info} {len(entries)} entries  |  use --get <ID> for full detail")


if __name__ == "__main__":
    main()
