#!/usr/bin/python3
"""
CI/CD Runner — Pipeline-native security scanning with baseline diffing.

Addresses the #1 DAST CI/CD pain point: too much noise from existing tools.
This runner:
  1. Runs a configured scan profile against a target
  2. Saves a baseline result set on first run
  3. On subsequent runs, diffs against baseline → only NEW findings reported
  4. Exits with configurable exit codes (useful for pipeline gates)
  5. Outputs machine-readable JSON + optional SARIF (GitHub Code Scanning)
  6. Supports severity thresholds per pipeline stage

Usage:
  # First run (save baseline)
  ../.venv/bin/python3 modules/cicd_runner.py -u https://staging.app.com --save-baseline

  # Subsequent runs (diff mode)
  ../.venv/bin/python3 modules/cicd_runner.py -u https://staging.app.com
  # → exits 0 if no new HIGH+ findings, exits 1 if new findings above threshold

  # Full scan with output
  ../.venv/bin/python3 modules/cicd_runner.py -u https://staging.app.com \\
      --profile full --severity high --output scan.json --sarif scan.sarif

  # GitHub Actions integration
  ../.venv/bin/python3 modules/cicd_runner.py -u $TARGET_URL \\
      --pr-comment --github-token $GITHUB_TOKEN --pr $PR_NUMBER --repo owner/repo
"""
import argparse
import json
import os
import sys
import time
import hashlib
import urllib.parse
from datetime import datetime, timezone

from core.colors import bold, end, good, bad, info, run

_CONFIG_DIR   = os.path.expanduser("~/.catch403/cicd")
_BASELINE_DIR = os.path.join(_CONFIG_DIR, "baselines")

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ── scan profiles ─────────────────────────────────────────────────────────

# Profile → list of (module_name, kwargs)
# We import modules lazily to avoid import errors for optional deps
PROFILES: dict[str, list[tuple[str, dict]]] = {
    "quick": [
        ("security_headers", {}),
        ("ssl_tls_scanner",  {}),
        ("cors_scanner",     {}),
        ("fingerprint",      {}),
    ],
    "standard": [
        ("security_headers", {}),
        ("ssl_tls_scanner",  {}),
        ("cors_scanner",     {}),
        ("fingerprint",      {}),
        ("cookie_analyser",  {}),
        ("content_discovery", {"max_workers": 5}),
        ("crlf_scanner",     {}),
        ("open_redirect",    {}),
    ],
    "full": [
        ("security_headers", {}),
        ("ssl_tls_scanner",  {}),
        ("cors_scanner",     {}),
        ("fingerprint",      {}),
        ("cookie_analyser",  {}),
        ("content_discovery", {"max_workers": 10}),
        ("param_miner",      {}),
        ("crlf_scanner",     {}),
        ("open_redirect",    {}),
        ("ssrf_scanner",     {}),
        ("ssti_scanner",     {}),
        ("secret_finder",    {}),
        ("jwt_analyser",     {}),
        ("active_scan",      {}),
    ],
    "api": [
        ("cors_scanner",        {}),
        ("security_headers",    {}),
        ("param_miner",         {}),
        ("ssrf_scanner",        {}),
        ("ssti_scanner",        {}),
        ("nosql_scanner",       {}),
        ("prototype_pollution", {}),
    ],
}


# ── finding fingerprinting ─────────────────────────────────────────────────

def _fingerprint(finding: dict) -> str:
    """Stable fingerprint for deduplication — name + url + param."""
    parts = [
        finding.get("name", ""),
        finding.get("url", ""),
        finding.get("param", ""),
    ]
    return hashlib.md5("|".join(parts).encode()).hexdigest()


def _above_threshold(finding: dict, min_severity: str) -> bool:
    min_order = _SEV_ORDER.get(min_severity, 99)
    finding_order = _SEV_ORDER.get(finding.get("severity", "info"), 4)
    return finding_order <= min_order


# ── baseline management ────────────────────────────────────────────────────

def _baseline_path(target: str, profile: str) -> str:
    os.makedirs(_BASELINE_DIR, exist_ok=True)
    slug = hashlib.md5(f"{target}|{profile}".encode()).hexdigest()[:12]
    return os.path.join(_BASELINE_DIR, f"{slug}.json")


def load_baseline(target: str, profile: str) -> dict[str, dict]:
    """Load baseline fingerprint → finding dict."""
    path = _baseline_path(target, profile)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path) as fh:
            data = json.load(fh)
        return {item["_fingerprint"]: item for item in data}
    except Exception:
        return {}


def save_baseline(target: str, profile: str, findings: list[dict]):
    path = _baseline_path(target, profile)
    stamped = []
    for f in findings:
        item = dict(f)
        item["_fingerprint"] = _fingerprint(f)
        item["_baseline_at"] = datetime.now(timezone.utc).isoformat()
        stamped.append(item)
    with open(path, "w") as fh:
        json.dump(stamped, fh, indent=2)
    return path


def diff_against_baseline(current: list[dict],
                           baseline: dict[str, dict]) -> list[dict]:
    """Return findings in current that are NOT in the baseline."""
    new_findings = []
    for f in current:
        fp = _fingerprint(f)
        if fp not in baseline:
            f["_new"] = True
            new_findings.append(f)
    return new_findings


# ── scan runner ───────────────────────────────────────────────────────────

def run_scan(url: str, profile: str = "standard",
             cookie: str = "", extra_headers: dict | None = None) -> list[dict]:
    """Run the configured scan profile against url."""
    all_findings: list[dict] = []
    modules_config = PROFILES.get(profile, PROFILES["standard"])

    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme
    host   = parsed.netloc

    for module_name, kwargs in modules_config:
        print(f"  {run} {module_name}", end="", flush=True)
        t0 = time.time()
        try:
            mod = _import_module(module_name)
            if mod is None:
                print(f" [skip — not available]")
                continue

            scan_fn = getattr(mod, "scan", None)
            if scan_fn is None:
                print(f" [skip — no scan()]")
                continue

            # Build kwargs appropriate to this module
            call_kw: dict = {}
            call_kw.update(kwargs)

            import inspect
            sig = inspect.signature(scan_fn)
            params = sig.parameters

            if "cookie" in params and cookie:
                call_kw["cookie"] = cookie
            if "headers" in params and extra_headers:
                call_kw["headers"] = extra_headers
            if "url" in params or len(sig.parameters) > 0:
                findings = scan_fn(url, **call_kw)
            else:
                findings = scan_fn(**call_kw)

            if isinstance(findings, list):
                for f in findings:
                    f.setdefault("_source", module_name)
                all_findings.extend(findings)

            elapsed = time.time() - t0
            count = len([f for f in (findings or []) if f.get("severity") != "info"])
            print(f" [{elapsed:.1f}s, {count} finding(s)]")

        except Exception as e:
            print(f" [error: {e}]")

    return all_findings


def _import_module(name: str):
    """Safely import a scan module by name."""
    try:
        import importlib
        return importlib.import_module(f"modules.{name}")
    except ImportError:
        return None


# ── SARIF output ──────────────────────────────────────────────────────────

def to_sarif(findings: list[dict], target: str) -> dict:
    """Convert findings to SARIF 2.1.0 format (GitHub Code Scanning compatible)."""
    rules = []
    results = []
    seen_rule_ids: set[str] = set()

    for f in findings:
        rule_id = hashlib.md5(f.get("name", "unknown").encode()).hexdigest()[:8]
        if rule_id not in seen_rule_ids:
            seen_rule_ids.add(rule_id)
            sev_map = {"critical": "error", "high": "error",
                       "medium": "warning", "low": "note", "info": "none"}
            rules.append({
                "id":   rule_id,
                "name": f.get("name", "Unknown"),
                "shortDescription": {"text": f.get("name", "Unknown")},
                "helpUri": f.get("references", ["https://owasp.org"])[0] if f.get("references") else "https://owasp.org",
                "defaultConfiguration": {
                    "level": sev_map.get(f.get("severity", "info"), "note")
                },
            })

        results.append({
            "ruleId":  rule_id,
            "message": {"text": f.get("detail", f.get("name", ""))[:500]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.get("url", target),
                    }
                }
            }],
            "level": {"critical": "error", "high": "error",
                      "medium": "warning", "low": "note"}.get(f.get("severity", "info"), "note"),
        })

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name":    "Catch403",
                    "version": "1.0.0",
                    "rules":   rules,
                }
            },
            "results": results,
        }]
    }


# ── GitHub PR comment ─────────────────────────────────────────────────────

def post_github_comment(findings: list[dict], pr: int, repo: str,
                        token: str, baseline_mode: bool = True):
    """Post a PR comment with finding summary."""
    import requests as _requests

    new_count = len([f for f in findings if f.get("severity") not in ("info", "meta")])
    critical  = len([f for f in findings if f.get("severity") == "critical"])
    high      = len([f for f in findings if f.get("severity") == "high"])
    medium    = len([f for f in findings if f.get("severity") == "medium"])

    status_emoji = "🔴" if critical else ("🟠" if high else ("🟡" if medium else "🟢"))
    label = "NEW " if baseline_mode else ""

    lines = [
        f"## {status_emoji} Catch403 Security Scan Results",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 Critical | {critical} |",
        f"| 🟠 High     | {high} |",
        f"| 🟡 Medium   | {medium} |",
        f"",
    ]

    if findings:
        lines += [f"### {label}Findings", ""]
        for f in sorted(findings, key=lambda x: _SEV_ORDER.get(x.get("severity", "info"), 9)):
            sev = f.get("severity", "info").upper()
            name = f.get("name", "Unknown")
            url  = f.get("url", "")
            lines.append(f"- **[{sev}]** {name}" + (f" — `{url[:80]}`" if url else ""))
    else:
        lines.append("✅ No new findings above threshold.")

    body = "\n".join(lines)

    url = f"https://api.github.com/repos/{repo}/issues/{pr}/comments"
    resp = _requests.post(
        url, json={"body": body},
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"},
        timeout=15,
    )
    return resp.status_code in (200, 201)


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Catch403 CI/CD Runner — Pipeline-native security scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # First run — save baseline
  cicd_runner.py -u https://staging.app.com --save-baseline

  # Subsequent runs — diff only
  cicd_runner.py -u https://staging.app.com

  # Full scan, fail on high+
  cicd_runner.py -u https://staging.app.com --profile full --severity high

  # GitHub Actions with PR comment
  cicd_runner.py -u $URL --github-token $TOKEN --pr $PR --repo owner/repo
"""
    )
    parser.add_argument("-u", dest="url", required=True)
    parser.add_argument("--profile", default="standard",
                        choices=list(PROFILES.keys()),
                        help="Scan profile (default: standard)")
    parser.add_argument("--severity", default="high",
                        choices=["critical", "high", "medium", "low"],
                        help="Minimum severity to fail the pipeline (default: high)")
    parser.add_argument("--save-baseline", action="store_true",
                        help="Save current results as baseline (no exit code)")
    parser.add_argument("--no-diff", action="store_true",
                        help="Report all findings, not just new ones")
    parser.add_argument("--cookie",  default="")
    parser.add_argument("--header",  dest="headers", action="append", default=[],
                        metavar="NAME:VALUE")
    parser.add_argument("--output",  default="", metavar="FILE",
                        help="Save full results to JSON file")
    parser.add_argument("--sarif",   default="", metavar="FILE",
                        help="Save SARIF output (GitHub Code Scanning)")
    parser.add_argument("--github-token", default="", metavar="TOKEN")
    parser.add_argument("--pr",      type=int, default=0, metavar="NUMBER")
    parser.add_argument("--repo",    default="", metavar="OWNER/REPO")
    args = parser.parse_args()

    extra_headers: dict = {}
    for h in args.headers:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    _p = urllib.parse.urlparse(args.url)
    print(f"\n{run} Catch403 CI/CD Runner")
    print(f"     Target:  {bold}{_p.netloc}{end}")
    print(f"     Profile: {args.profile}")
    print(f"     Mode:    {'baseline save' if args.save_baseline else 'diff' if not args.no_diff else 'full'}\n")

    start = time.time()
    findings = run_scan(args.url, args.profile, args.cookie, extra_headers)
    elapsed = time.time() - start

    # Filter out meta/info
    real_findings = [f for f in findings if f.get("severity") not in ("meta",)]

    # Save baseline if requested
    if args.save_baseline:
        path = save_baseline(args.url, args.profile, real_findings)
        total = len(real_findings)
        print(f"\n{good} Baseline saved: {path}")
        print(f"     {total} finding(s) recorded as baseline")
        if args.output:
            with open(args.output, "w") as fh:
                json.dump(real_findings, fh, indent=2)
        sys.exit(0)

    # Diff against baseline
    baseline = {}
    reported = real_findings
    if not args.no_diff:
        baseline = load_baseline(args.url, args.profile)
        if baseline:
            reported = diff_against_baseline(real_findings, baseline)
            print(f"\n{info} Baseline: {len(baseline)} known finding(s)")
            print(f"{info} New:      {len(reported)} new finding(s)\n")
        else:
            print(f"\n{info} No baseline found — reporting all findings (run --save-baseline first)\n")

    # Print results
    above_threshold = [f for f in reported if _above_threshold(f, args.severity)]
    by_sev = {}
    for f in reported:
        s = f.get("severity", "info")
        by_sev[s] = by_sev.get(s, 0) + 1

    print(f"\n{'─'*60}")
    print(f"  Findings summary ({elapsed:.1f}s)")
    for sev in ("critical", "high", "medium", "low", "info"):
        n = by_sev.get(sev, 0)
        if n:
            col = "\033[91m" if sev == "critical" else "\033[33m" if sev in ("high", "medium") else "\033[37m"
            print(f"    {col}{sev.upper():<10}\033[0m {n}")

    if above_threshold:
        print(f"\n  Findings above threshold ({args.severity}+):\n")
        for f in sorted(above_threshold, key=lambda x: _SEV_ORDER.get(x.get("severity", "info"), 9)):
            sev = f.get("severity", "info").upper()
            print(f"  [{sev}] {f.get('name', '')}")
            if f.get("url"):
                print(f"         {f['url']}")
    print(f"{'─'*60}\n")

    # Save outputs
    if args.output:
        with open(args.output, "w") as fh:
            json.dump(reported, fh, indent=2)
        print(f"{good} Results saved to {args.output}")

    if args.sarif:
        sarif = to_sarif(reported, args.url)
        with open(args.sarif, "w") as fh:
            json.dump(sarif, fh, indent=2)
        print(f"{good} SARIF saved to {args.sarif}")

    if args.github_token and args.pr and args.repo:
        ok = post_github_comment(
            above_threshold, args.pr, args.repo, args.github_token,
            baseline_mode=bool(baseline)
        )
        print(f"{good if ok else bad} GitHub PR comment {'posted' if ok else 'failed'}")

    # Exit code
    exit_code = 1 if above_threshold else 0
    if exit_code:
        print(f"{bad} Pipeline gate FAILED — {len(above_threshold)} finding(s) above {args.severity} threshold")
    else:
        print(f"{good} Pipeline gate PASSED")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
