#!/usr/bin/python3
"""
SQLMap Scanner — sqlmap integration for Catch403.

Runs sqlmap with --batch and captures injection findings, DBMS fingerprint,
tables, and dumped data. All output is parsed back into the standard finding
format so results appear in the web UI and logger.

Usage:
  ../.venv/bin/python3 modules/sqlmap_scanner.py -u "https://target.com/page?id=1"
  ../.venv/bin/python3 modules/sqlmap_scanner.py -u "https://target.com/login" -d "user=admin&pass=x"
  ../.venv/bin/python3 modules/sqlmap_scanner.py -u "https://target.com/page?id=1" --level 3 --risk 2
  ../.venv/bin/python3 modules/sqlmap_scanner.py -u "https://target.com/page?id=1" --dbs --tables --dump
  ../.venv/bin/python3 modules/sqlmap_scanner.py -u "https://target.com/page?id=1" --proxy http://127.0.0.1:8080
  ../.venv/bin/python3 modules/sqlmap_scanner.py -u "https://target.com/page?id=1" -o results.json
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse

from core.colors import bold, end, good, bad, info, run
from core.auth_gate import preflight

# ── sqlmap binary location ─────────────────────────────────────────────────

_HERE = os.path.dirname(os.path.abspath(__file__))

# Vendored GitHub clone is preferred — always latest HEAD.
# Fall back to venv pip install, then system PATH.
_VENDOR_SQLMAP = os.path.abspath(
    os.path.join(_HERE, "..", "..", "vendor", "sqlmap", "sqlmap.py")
)


def _sqlmap_bin() -> tuple[list[str], str]:
    """
    Return (command_prefix, version_label) for the best available sqlmap.

    Vendored GitHub clone is preferred over pip install — it tracks HEAD
    and is updated with `git pull vendor/sqlmap`.
    """
    if os.path.isfile(_VENDOR_SQLMAP):
        return ([sys.executable, _VENDOR_SQLMAP], "vendor/sqlmap (GitHub HEAD)")

    venv_bin = os.path.abspath(
        os.path.join(_HERE, "..", "..", ".venv", "bin", "sqlmap")
    )
    if os.path.isfile(venv_bin):
        return ([venv_bin], "pip install sqlmap")

    found = shutil.which("sqlmap")
    if found:
        return ([found], "system sqlmap")

    raise RuntimeError(
        "sqlmap not found.\n"
        "  Option A (recommended): clone from GitHub into vendor/\n"
        "    git clone --depth=1 https://github.com/sqlmapproject/sqlmap.git vendor/sqlmap\n"
        "  Option B: pip install sqlmap"
    )


# ── output parsing ─────────────────────────────────────────────────────────

# Patterns matched against sqlmap's log file lines
_INJECTABLE = re.compile(
    r"\[INFO\] ((?:GET|POST|PUT|Cookie|URI|User-Agent|Referer|Host) parameter '(.+?)' "
    r"(?:appears to be|is) '(.+?)' injectable)"
)
_DBMS = re.compile(r"\[INFO\] the back-end DBMS is (.+)")
_CURRENT_DB = re.compile(r"\[INFO\] fetching current database.*?'(.+?)'", re.DOTALL)
_CURRENT_USER = re.compile(r"\[INFO\] fetching current user.*?'(.+?)'", re.DOTALL)
_DB_LIST = re.compile(r"\[INFO\] fetching database names.*?\[(\d+) entries\]")
_TABLE_LIST = re.compile(r"\[INFO\] fetching tables for database.*?\[(\d+) tables\]")
_DUMP_LINE = re.compile(r"\[INFO\] fetching entries")
_OS_INFO = re.compile(r"\[INFO\] the remote operating system is '(.+?)'")
_NOT_INJECTABLE = re.compile(r"\[CRITICAL\] all tested parameters do not appear to be injectable")
_PAYLOAD = re.compile(r"Payload: (.+)")


def _parse_log(log_text: str) -> list[dict]:
    findings = []
    seen_params = set()

    for line in log_text.splitlines():
        m = _INJECTABLE.search(line)
        if m:
            full_desc, param, technique = m.group(1), m.group(2), m.group(3)
            key = (param, technique)
            if key not in seen_params:
                seen_params.add(key)
                findings.append({
                    "name": f"SQL Injection — parameter '{param}'",
                    "severity": "critical",
                    "detail": technique,
                    "param": param,
                })

        m = _DBMS.search(line)
        if m:
            findings.append({
                "name": "DBMS Fingerprint",
                "severity": "info",
                "detail": m.group(1).strip(),
            })

        m = _OS_INFO.search(line)
        if m:
            findings.append({
                "name": "Remote OS",
                "severity": "info",
                "detail": m.group(1).strip(),
            })

        m = _CURRENT_USER.search(line)
        if m:
            findings.append({
                "name": "DB Current User",
                "severity": "high",
                "detail": m.group(1).strip(),
            })

    if not findings and _NOT_INJECTABLE.search(log_text):
        findings.append({
            "name": "Not injectable",
            "severity": "info",
            "detail": "No SQL injection found in tested parameters",
        })

    # Extract unique payloads and attach to the first injectable finding
    payloads = list(dict.fromkeys(
        m.group(1).strip()
        for m in _PAYLOAD.finditer(log_text)
    ))
    if payloads:
        inj = next((f for f in findings if f["severity"] == "critical"), None)
        if inj:
            inj["payloads"] = payloads[:10]

    return findings


def _parse_dump_dir(output_dir: str) -> list[dict]:
    """Walk the dump/ subdirectory and read any CSV files sqlmap created."""
    findings = []
    dump_root = os.path.join(output_dir)
    for dirpath, _dirs, files in os.walk(dump_root):
        for fname in files:
            if fname.endswith(".csv"):
                fpath = os.path.join(dirpath, fname)
                rel = os.path.relpath(fpath, output_dir)
                try:
                    with open(fpath) as fh:
                        rows = fh.read().strip()
                    preview = rows[:500] + ("…" if len(rows) > 500 else "")
                    findings.append({
                        "name": f"Dumped data — {rel}",
                        "severity": "critical",
                        "detail": preview,
                    })
                except OSError:
                    pass
    return findings


# ── main scanner ───────────────────────────────────────────────────────────

def scan(
    url: str,
    *,
    data: str = "",
    cookie: str = "",
    param: str = "",
    level: int = 1,
    risk: int = 1,
    dbms: str = "",
    technique: str = "",
    threads: int = 5,
    timeout: int = 30,
    proxy: str = "",
    get_dbs: bool = False,
    get_tables: bool = False,
    do_dump: bool = False,
    extra_args: list[str] | None = None,
) -> list[dict]:
    """
    Run sqlmap against url and return findings as list[dict].

    Parameters mirror common sqlmap CLI flags. All runs use --batch so no
    interactive prompts appear.
    """
    sqlmap_cmd, _source = _sqlmap_bin()
    tmp = tempfile.mkdtemp(prefix="catch403_sqlmap_")

    cmd = [
        *sqlmap_cmd,
        "-u", url,
        "--batch",
        "--output-dir", tmp,
        f"--level={level}",
        f"--risk={risk}",
        f"--threads={threads}",
        f"--timeout={timeout}",
        "--no-logging",   # suppress per-host logging noise to stderr
        "--disable-coloring",
    ]

    if data:
        cmd += ["--data", data]
    if cookie:
        cmd += ["--cookie", cookie]
    if param:
        cmd += ["-p", param]
    if dbms:
        cmd += ["--dbms", dbms]
    if technique:
        cmd += ["--technique", technique]
    if proxy:
        cmd += ["--proxy", proxy]
    if get_dbs:
        cmd.append("--dbs")
    if get_tables:
        cmd.append("--tables")
    if do_dump:
        cmd.append("--dump")
    if extra_args:
        cmd += extra_args

    findings: list[dict] = []

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
        combined = proc.stdout + "\n" + proc.stderr

        findings = _parse_log(combined)
        findings += _parse_dump_dir(tmp)

        # Attach raw sqlmap output as a meta-finding so the caller can inspect
        findings.append({
            "name": "_sqlmap_raw",
            "severity": "meta",
            "detail": combined[-8000:],   # last 8 KB to keep it bounded
        })
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return findings


# ── CLI ────────────────────────────────────────────────────────────────────

def _print_finding(f: dict) -> None:
    sev = f.get("severity", "info")
    name = f.get("name", "")
    detail = f.get("detail", "")

    if sev == "critical":
        prefix = bad
    elif sev == "high":
        prefix = f"{bold}[HIGH]{end}"
    elif sev == "meta":
        return   # raw output — only written to -o file
    else:
        prefix = info

    print(f"{prefix} {bold}{name}{end}")
    if detail:
        print(f"        {detail}")
    if "payloads" in f:
        for p in f["payloads"]:
            print(f"        Payload: {p}")


def main():
    parser = argparse.ArgumentParser(
        description="Catch403 SQLMap Scanner — sqlmap integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", dest="url", required=True, metavar="URL",
                        help="Target URL (include injectable parameter, e.g. ?id=1)")
    parser.add_argument("-d", dest="data", default="", metavar="DATA",
                        help="POST data body (marks injectable parameter with *)")
    parser.add_argument("--cookie", default="", help="Cookie header value")
    parser.add_argument("-p", dest="param", default="", metavar="PARAM",
                        help="Test specific parameter only")
    parser.add_argument("--level", type=int, default=1, choices=range(1, 6),
                        metavar="1-5", help="Test level (default: 1)")
    parser.add_argument("--risk", type=int, default=1, choices=range(1, 4),
                        metavar="1-3", help="Risk level (default: 1)")
    parser.add_argument("--dbms", default="",
                        help="Force back-end DBMS (mysql, postgresql, mssql, oracle, sqlite…)")
    parser.add_argument("--technique", default="", metavar="BEUSTQ",
                        help="SQLi techniques: B=boolean, E=error, U=union, S=stacked, T=time, Q=inline")
    parser.add_argument("-t", "--threads", type=int, default=5, metavar="N",
                        help="Concurrent threads (default: 5)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Per-request timeout seconds (default: 30)")
    parser.add_argument("--proxy", default="",
                        help="Use proxy, e.g. http://127.0.0.1:8080 to route through Catch403")
    parser.add_argument("--dbs", action="store_true", help="Enumerate databases")
    parser.add_argument("--tables", action="store_true", help="Enumerate tables")
    parser.add_argument("--dump", action="store_true", help="Dump table contents")
    parser.add_argument("--raw", action="store_true",
                        help="Also print raw sqlmap output")
    parser.add_argument("-o", dest="output", default="",
                        help="Save findings to JSON file")
    args = parser.parse_args()

    preflight('sqlmap_scanner', args.url, active=True)

    parsed = urllib.parse.urlparse(args.url)
    print(f"{run} Starting sqlmap against {bold}{parsed.netloc}{parsed.path}{end}")
    print(f"{info} Level {args.level}  Risk {args.risk}  Threads {args.threads}")
    if args.proxy:
        print(f"{info} Proxy: {args.proxy}")
    print()

    try:
        _, source_label = _sqlmap_bin()
        print(f"{info} Using: {source_label}")
    except RuntimeError as e:
        print(f"{bad} {e}")
        sys.exit(1)

    results = scan(
        args.url,
        data=args.data,
        cookie=args.cookie,
        param=args.param,
        level=args.level,
        risk=args.risk,
        dbms=args.dbms,
        technique=args.technique,
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
        get_dbs=args.dbs,
        get_tables=args.tables,
        do_dump=args.dump,
    )

    raw = next((f for f in results if f.get("name") == "_sqlmap_raw"), None)

    visible = [f for f in results if f.get("severity") != "meta"]
    for f in visible:
        _print_finding(f)

    if args.raw and raw:
        print(f"\n{info} Raw sqlmap output:\n")
        print(raw["detail"])

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(visible, fh, indent=2)
        print(f"\n{good} Findings saved to {args.output}")

    print()
    inj = [f for f in visible if f.get("severity") == "critical"]
    if inj:
        print(f"{good} {len(inj)} injectable parameter(s) found")
    else:
        print(f"{info} No injection found (try --level 3 --risk 2 for deeper coverage)")


if __name__ == "__main__":
    main()
