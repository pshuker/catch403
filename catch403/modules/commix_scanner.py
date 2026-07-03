#!/usr/bin/python3
"""
Commix Scanner — command injection automation for Catch403.

Wraps the vendored commixproject/commix (vendor/commix/) with --batch mode
and parses findings into the standard dict format.

Usage:
  ../.venv/bin/python3 modules/commix_scanner.py -u "https://target.com/page?id=1"
  ../.venv/bin/python3 modules/commix_scanner.py -u "https://target.com/login" -d "user=admin&cmd=id"
  ../.venv/bin/python3 modules/commix_scanner.py -u "https://target.com/page?id=1" --level 2 --technique classic
  ../.venv/bin/python3 modules/commix_scanner.py -u "https://target.com/page?id=1" --proxy http://127.0.0.1:8080
  ../.venv/bin/python3 modules/commix_scanner.py -u "https://target.com/page?id=1" -o results.json
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

_HERE = os.path.dirname(os.path.abspath(__file__))
_VENDOR = os.path.abspath(os.path.join(_HERE, "..", "..", "vendor", "commix", "commix.py"))


def _commix_bin() -> tuple[list[str], str]:
    if os.path.isfile(_VENDOR):
        return ([sys.executable, _VENDOR], "vendor/commix (GitHub HEAD)")
    found = shutil.which("commix")
    if found:
        return ([found], "system commix")
    raise RuntimeError(
        "commix not found.\n"
        "  git clone --depth=1 https://github.com/commixproject/commix.git vendor/commix"
    )


# ── output parsing ─────────────────────────────────────────────────────────

_INJECTABLE = re.compile(
    r"\[\+\].*?(?:parameter|value) ['\"](.+?)['\"].*?(?:appears to be|is) injectable",
    re.IGNORECASE,
)
_TECHNIQUE = re.compile(
    r"\[\+\].*?(classic|eval-based|time-based|file-based)[- ]command injection",
    re.IGNORECASE,
)
_SHELL_PROMPT = re.compile(r"\[\+\].*?pseudo-terminal shell", re.IGNORECASE)
_NOT_INJECTABLE = re.compile(
    r"(?:not injectable|appear to be not injectable|no results|unable to detect|not vulnerable)",
    re.IGNORECASE,
)
_OS_SHELL = re.compile(r"\[\+\].*?OS shell.*?obtained", re.IGNORECASE)
_PAYLOAD = re.compile(r"\[payload\]\s*(.+)", re.IGNORECASE)


def _parse_output(text: str) -> list[dict]:
    findings = []
    seen = set()

    for line in text.splitlines():
        m = _INJECTABLE.search(line)
        if m:
            param = m.group(1)
            if param not in seen:
                seen.add(param)
                findings.append({
                    "name": f"Command Injection — parameter '{param}'",
                    "severity": "critical",
                    "detail": line.strip(),
                    "param": param,
                })

        m = _TECHNIQUE.search(line)
        if m and findings:
            technique = m.group(1).lower()
            findings[-1].setdefault("techniques", []).append(technique)

        if _OS_SHELL.search(line):
            findings.append({
                "name": "OS Shell obtained",
                "severity": "critical",
                "detail": "commix achieved OS-level command execution",
            })

    payloads = [m.group(1).strip() for m in _PAYLOAD.finditer(text)]
    if payloads:
        inj = next((f for f in findings if f["severity"] == "critical"), None)
        if inj:
            inj["payloads"] = list(dict.fromkeys(payloads))[:10]

    if not findings and _NOT_INJECTABLE.search(text):
        findings.append({
            "name": "Not injectable",
            "severity": "info",
            "detail": "No command injection found in tested parameters",
        })

    return findings


# ── main scanner ───────────────────────────────────────────────────────────

_TECHNIQUE_MAP = {
    "classic":    "--technique=classic",
    "eval":       "--technique=eval-based",
    "time":       "--technique=time-based",
    "file":       "--technique=file-based",
}


def scan(
    url: str,
    *,
    data: str = "",
    cookie: str = "",
    param: str = "",
    level: int = 1,
    technique: str = "",
    proxy: str = "",
    timeout: int = 30,
    extra_args: list[str] | None = None,
) -> list[dict]:
    cmd_prefix, _source = _commix_bin()
    tmp = tempfile.mkdtemp(prefix="catch403_commix_")
    log_file = os.path.join(tmp, "output.txt")

    cmd = [
        *cmd_prefix,
        "--url", url,
        "--batch",
        "--output-dir", tmp,
        f"--level={level}",
        f"--timeout={timeout}",
        "--disable-coloring",
    ]
    if data:
        cmd += ["--data", data]
    if cookie:
        cmd += ["--cookie", cookie]
    if param:
        cmd += ["-p", param]
    if technique and technique in _TECHNIQUE_MAP:
        cmd.append(_TECHNIQUE_MAP[technique])
    if proxy:
        cmd += ["--proxy", proxy]
    if extra_args:
        cmd += extra_args

    findings: list[dict] = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        combined = proc.stdout + "\n" + proc.stderr
        findings = _parse_output(combined)
        findings.append({
            "name": "_commix_raw",
            "severity": "meta",
            "detail": combined[-8000:],
        })
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return findings


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Catch403 Commix Scanner")
    parser.add_argument("-u", dest="url", required=True)
    parser.add_argument("-d", dest="data", default="")
    parser.add_argument("--cookie", default="")
    parser.add_argument("-p", dest="param", default="")
    parser.add_argument("--level", type=int, default=1, choices=range(1, 4), metavar="1-3")
    parser.add_argument("--technique", default="",
                        choices=["classic", "eval", "time", "file"],
                        help="Injection technique (default: all)")
    parser.add_argument("--proxy", default="")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--raw", action="store_true", help="Print raw commix output")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    preflight('commix_scanner', args.url, active=True)

    parsed = urllib.parse.urlparse(args.url)
    print(f"{run} Starting commix against {bold}{parsed.netloc}{parsed.path}{end}")

    try:
        _, label = _commix_bin()
        print(f"{info} Using: {label}")
    except RuntimeError as e:
        print(f"{bad} {e}")
        sys.exit(1)

    results = scan(
        args.url, data=args.data, cookie=args.cookie,
        param=args.param, level=args.level, technique=args.technique,
        proxy=args.proxy, timeout=args.timeout,
    )

    raw = next((f for f in results if f.get("name") == "_commix_raw"), None)
    visible = [f for f in results if f.get("severity") != "meta"]

    for f in visible:
        sev = f.get("severity", "info")
        prefix = bad if sev == "critical" else info
        print(f"{prefix} {bold}{f['name']}{end}")
        if f.get("detail"):
            print(f"        {f['detail']}")
        for p in f.get("payloads", []):
            print(f"        Payload: {p}")

    if args.raw and raw:
        print(f"\n{info} Raw commix output:\n{raw['detail']}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(visible, fh, indent=2)
        print(f"\n{good} Saved to {args.output}")

    inj = [f for f in visible if f.get("severity") == "critical"]
    print()
    if inj:
        print(f"{good} {len(inj)} injectable point(s) found")
    else:
        print(f"{info} No command injection found")


if __name__ == "__main__":
    main()
