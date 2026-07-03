#!/usr/bin/python3
"""
Report Generator — professional HTML pentest report from Catch403 findings.

Pulls findings from FindingTracker (or a JSON file) and generates a
self-contained HTML report: cover page, executive summary, severity chart,
findings table, and detailed cards with evidence and remediation.

Usage:
  ../.venv/bin/python3 modules/report_generator.py --target "Acme Corp" --tester "Pedro" -o report.html
  ../.venv/bin/python3 modules/report_generator.py --findings findings.json -o report.html
  ../.venv/bin/python3 modules/report_generator.py --status confirmed -o confirmed_only.html
  ../.venv/bin/python3 modules/report_generator.py --target "Client" --scope "https://target.com" -o report.html
"""
import argparse
import html
import json
import os
import sys
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_COLOUR = {
    "critical": "#e05252",
    "high":     "#e07a52",
    "medium":   "#e0a458",
    "low":      "#4c8dff",
    "info":     "#5a6b80",
}
_REMEDIATION = {
    "SQL Injection":             "Use parameterised queries / prepared statements. Never concatenate user input into SQL strings.",
    "Command Injection":         "Avoid passing user input to OS commands. Use safe APIs that don't invoke a shell.",
    "Cross-Site Scripting":      "Encode all output with context-aware escaping. Implement a strict Content-Security-Policy.",
    "CORS":                      "Restrict Access-Control-Allow-Origin to explicit trusted origins. Never reflect arbitrary origins.",
    "CSRF":                      "Implement synchronised token pattern or SameSite=Strict cookie attribute.",
    "Clickjacking":              "Set X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'.",
    "HSTS":                      "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.",
    "Certificate":               "Renew the certificate before expiry. Use a trusted CA. Ensure CN/SAN matches the hostname.",
    "Path Traversal":            "Validate and canonicalise file paths server-side. Use allow-lists for permitted paths.",
    "Open Redirect":             "Validate redirect targets against an explicit allow-list of trusted URLs.",
    "SSRF":                      "Validate URLs server-side. Block internal IP ranges. Use an egress proxy with deny-by-default.",
    "XXE":                       "Disable external entity processing in the XML parser. Use a safe parser configuration.",
    "LDAP":                      "Use parameterised LDAP queries. Escape special characters in all user-supplied input.",
    "NoSQL":                     "Use ODM/query builder with typed operators. Never pass raw user input into query objects.",
    "Default Credentials":       "Change all default credentials before deployment. Enforce a strong password policy.",
    "User Enumeration":          "Return identical responses for valid and invalid usernames. Implement rate limiting.",
    "Cookie":                    "Set HttpOnly, Secure, and SameSite attributes on all session cookies.",
    "Session Fixation":          "Issue a new session token immediately after successful authentication.",
    "TLS":                       "Disable SSLv2/3 and TLS 1.0/1.1. Configure only strong cipher suites (AES-GCM, ChaCha20).",
    "Recon File":                "Remove sensitive files from the web root (.env, .git, phpinfo.php, backup archives).",
}


def _remediation_for(finding: dict) -> str:
    name = finding.get("name", "").lower()
    for key, text in _REMEDIATION.items():
        if key.lower() in name:
            return text
    return "Review the finding detail and apply the principle of least privilege. Consult OWASP guidelines for the relevant vulnerability class."


def _h(text: str) -> str:
    return html.escape(str(text or ""))


def _severity_badge(sev: str) -> str:
    colour = _SEV_COLOUR.get(sev, "#5a6b80")
    return f'<span class="badge" style="background:{colour}">{_h(sev.upper())}</span>'


def _chart_bars(by_sev: dict) -> str:
    bars = ""
    total = max(sum(by_sev.values()), 1)
    for sev in ("critical", "high", "medium", "low", "info"):
        n = by_sev.get(sev, 0)
        if not n:
            continue
        pct = int(n / total * 100)
        colour = _SEV_COLOUR[sev]
        bars += f"""
        <div class="bar-row">
          <span class="bar-label">{sev.upper()}</span>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct}%;background:{colour}"></div>
          </div>
          <span class="bar-count">{n}</span>
        </div>"""
    return bars


def _finding_card(f: dict, idx: int) -> str:
    sev = f.get("severity", "info")
    colour = _SEV_COLOUR.get(sev, "#5a6b80")
    badge = _severity_badge(sev)
    remediation = _remediation_for(f)

    evidence_rows = ""
    if f.get("url"):
        evidence_rows += f'<tr><td>URL</td><td><code>{_h(f["url"])}</code></td></tr>'
    if f.get("param") or f.get("parameter"):
        evidence_rows += f'<tr><td>Parameter</td><td><code>{_h(f.get("param") or f.get("parameter",""))}</code></td></tr>'
    if f.get("payload"):
        evidence_rows += f'<tr><td>Payload</td><td><code>{_h(f["payload"])}</code></td></tr>'
    if f.get("method"):
        evidence_rows += f'<tr><td>Method</td><td><code>{_h(f["method"])}</code></td></tr>'

    http_block = ""
    if f.get("http_request"):
        http_block = f'<h4>HTTP Evidence</h4><pre class="code">{_h(f["http_request"][:2000])}</pre>'
    elif f.get("curl"):
        http_block = f'<h4>Curl Command</h4><pre class="code">{_h(f["curl"][:2000])}</pre>'

    notes_block = ""
    if f.get("notes"):
        notes_block = f'<div class="notes"><strong>Analyst Notes:</strong><br>{_h(f["notes"])}</div>'

    source = f.get("source_module", f.get("_source", ""))
    status = f.get("status", "")
    meta = ""
    if source or status:
        parts = []
        if source:
            parts.append(f"Source: {source}")
        if status:
            parts.append(f"Status: {status}")
        meta = f'<div class="meta-row">{" · ".join(parts)}</div>'

    return f"""
    <div class="finding-card" id="f{idx}" style="border-left:4px solid {colour}">
      <div class="finding-header">
        <span class="finding-num">F{idx:02d}</span>
        {badge}
        <span class="finding-title">{_h(f.get("name",""))}</span>
      </div>
      {meta}
      <div class="finding-body">
        <div class="section-label">Description</div>
        <p>{_h(f.get("detail",""))}</p>
        {"<table class='evidence-table'>" + evidence_rows + "</table>" if evidence_rows else ""}
        {http_block}
        <div class="section-label">Remediation</div>
        <p>{_h(remediation)}</p>
        {notes_block}
      </div>
    </div>"""


_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: #0f1419; color: #aab8c8; font-size: 14px; line-height: 1.6;
}
a { color: #4c8dff; }
code { font-family: 'JetBrains Mono','Consolas',monospace; font-size: 12px;
       background: #1a2230; padding: 2px 6px; border-radius: 3px; }
pre.code {
  background: #0a0e13; border: 1px solid #1e2733; border-radius: 6px;
  padding: 14px; overflow-x: auto; font-size: 11px; color: #aab8c8;
  white-space: pre-wrap; word-break: break-all; margin: 10px 0;
  font-family: 'JetBrains Mono','Consolas',monospace;
}
.page { max-width: 960px; margin: 0 auto; padding: 40px 24px; }

/* cover */
.cover {
  min-height: 60vh; display: flex; flex-direction: column;
  justify-content: center; border-bottom: 2px solid #1e2733; padding-bottom: 48px; margin-bottom: 48px;
}
.cover-logo { font-size: 13px; color: #4c8dff; letter-spacing: 3px;
              text-transform: uppercase; font-weight: 700; margin-bottom: 24px; }
.cover-title { font-size: 36px; font-weight: 700; color: #e8eef5; line-height: 1.2; margin-bottom: 8px; }
.cover-sub   { font-size: 18px; color: #5a6b80; margin-bottom: 40px; }
.cover-meta  { display: grid; grid-template-columns: 120px 1fr; gap: 8px 16px;
               color: #aab8c8; border-top: 1px solid #1e2733; padding-top: 24px; }
.cover-meta .label { color: #5a6b80; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }

/* section */
.section { margin-bottom: 48px; }
.section-title {
  font-size: 20px; font-weight: 600; color: #e8eef5;
  border-bottom: 1px solid #1e2733; padding-bottom: 10px; margin-bottom: 20px;
}
.section-label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
                 color: #5a6b80; margin: 16px 0 6px; }

/* exec summary */
.summary-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
  gap: 12px; margin-bottom: 24px;
}
.summary-card {
  background: #151b24; border: 1px solid #1e2733; border-radius: 8px;
  padding: 16px; text-align: center;
}
.summary-card .num { font-size: 32px; font-weight: 700; }
.summary-card .lbl { font-size: 11px; text-transform: uppercase;
                      letter-spacing: 1px; color: #5a6b80; margin-top: 4px; }

/* chart */
.bar-row { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
.bar-label { width: 72px; font-size: 11px; text-transform: uppercase;
             letter-spacing: 1px; color: #5a6b80; text-align: right; }
.bar-track { flex: 1; background: #1a2230; border-radius: 3px; height: 18px; overflow: hidden; }
.bar-fill  { height: 100%; border-radius: 3px; transition: width .3s; }
.bar-count { width: 32px; font-size: 13px; font-weight: 600; color: #e8eef5; }

/* findings table */
.findings-table { width: 100%; border-collapse: collapse; margin-bottom: 32px; }
.findings-table th {
  background: #151b24; color: #5a6b80; font-size: 11px;
  text-transform: uppercase; letter-spacing: 1px;
  padding: 10px 12px; text-align: left; border-bottom: 1px solid #1e2733;
}
.findings-table td { padding: 10px 12px; border-bottom: 1px solid #1a2230; vertical-align: top; }
.findings-table tr:hover td { background: #151b24; }
.findings-table .ref { color: #5a6b80; font-size: 12px; }

/* badge */
.badge {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 10px; font-weight: 700; letter-spacing: 1px;
  text-transform: uppercase; color: #fff;
}

/* finding cards */
.finding-card {
  background: #151b24; border-radius: 8px; margin-bottom: 24px;
  border: 1px solid #1e2733; overflow: hidden;
}
.finding-header {
  display: flex; align-items: center; gap: 10px;
  padding: 14px 18px; background: #0f1419; border-bottom: 1px solid #1e2733;
}
.finding-num   { font-size: 11px; color: #5a6b80; font-weight: 600; min-width: 28px; }
.finding-title { font-size: 15px; font-weight: 600; color: #e8eef5; }
.finding-body  { padding: 18px; }
.meta-row      { font-size: 11px; color: #5a6b80; padding: 6px 18px;
                 background: #0a0e13; border-bottom: 1px solid #1e2733; }
.evidence-table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 13px; }
.evidence-table td { padding: 5px 8px; border-bottom: 1px solid #1a2230; vertical-align: top; }
.evidence-table td:first-child { color: #5a6b80; font-size: 11px; text-transform: uppercase;
                                  letter-spacing: 1px; width: 100px; white-space: nowrap; }
.notes { background: #1a2230; border-left: 3px solid #4c8dff; border-radius: 4px;
         padding: 10px 14px; margin-top: 14px; font-size: 13px; }

/* footer */
.footer { border-top: 1px solid #1e2733; padding-top: 20px; margin-top: 48px;
          font-size: 11px; color: #5a6b80; text-align: center; }

@media print {
  body { background: #fff; color: #111; }
  .cover { min-height: auto; }
  .finding-card { break-inside: avoid; }
  pre.code { background: #f5f5f5; color: #333; border: 1px solid #ddd; }
}
"""


def generate(
    findings: list[dict],
    *,
    target: str = "Target",
    tester: str = "",
    scope: str = "",
    classification: str = "CONFIDENTIAL",
    status_filter: str = "",
    output: str = "report.html",
) -> str:
    if status_filter:
        allowed = {s.strip() for s in status_filter.split(",")}
        findings = [f for f in findings if f.get("status", "pending") in allowed]

    findings = [f for f in findings if f.get("severity") not in ("meta",)]
    findings.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 4))

    by_sev: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    date_str = datetime.now().strftime("%d %B %Y")
    total = len(findings)
    critical = by_sev.get("critical", 0)
    high = by_sev.get("high", 0)
    medium = by_sev.get("medium", 0)
    low = by_sev.get("low", 0)

    # Overall risk rating
    if critical:      risk, risk_colour = "CRITICAL", _SEV_COLOUR["critical"]
    elif high >= 3:   risk, risk_colour = "HIGH",     _SEV_COLOUR["high"]
    elif high:        risk, risk_colour = "HIGH",     _SEV_COLOUR["high"]
    elif medium >= 3: risk, risk_colour = "MEDIUM",   _SEV_COLOUR["medium"]
    elif medium:      risk, risk_colour = "MEDIUM",   _SEV_COLOUR["medium"]
    elif low:         risk, risk_colour = "LOW",      _SEV_COLOUR["low"]
    else:             risk, risk_colour = "INFO",     _SEV_COLOUR["info"]

    summary_cards = "".join(
        f'<div class="summary-card">'
        f'<div class="num" style="color:{_SEV_COLOUR[sev]}">{by_sev.get(sev,0)}</div>'
        f'<div class="lbl">{sev}</div></div>'
        for sev in ("critical","high","medium","low","info")
    )

    table_rows = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity","info")
        table_rows += (
            f'<tr><td class="ref"><a href="#f{i}">F{i:02d}</a></td>'
            f'<td>{_severity_badge(sev)}</td>'
            f'<td>{_h(f.get("name",""))}</td>'
            f'<td><code>{_h(f.get("url","")[:60])}</code></td>'
            f'<td>{_h(f.get("status",""))}</td></tr>'
        )

    cards = "".join(_finding_card(f, i) for i, f in enumerate(findings, 1))

    scope_row = f'<div class="label">Scope</div><div>{_h(scope)}</div>' if scope else ""
    tester_row = f'<div class="label">Tester</div><div>{_h(tester)}</div>' if tester else ""

    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Assessment — {_h(target)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="page">

  <!-- ── COVER ── -->
  <div class="cover">
    <div class="cover-logo">Catch403 · Security Assessment</div>
    <div class="cover-title">{_h(target)}</div>
    <div class="cover-sub">Web Application Penetration Test Report</div>
    <div class="cover-meta">
      <div class="label">Date</div><div>{date_str}</div>
      {tester_row}
      {scope_row}
      <div class="label">Classification</div><div>{_h(classification)}</div>
      <div class="label">Overall Risk</div>
      <div><span class="badge" style="background:{risk_colour};font-size:13px;padding:4px 12px">{risk}</span></div>
    </div>
  </div>

  <!-- ── EXECUTIVE SUMMARY ── -->
  <div class="section">
    <div class="section-title">Executive Summary</div>
    <div class="summary-grid">
      {summary_cards}
      <div class="summary-card">
        <div class="num" style="color:#e8eef5">{total}</div>
        <div class="lbl">Total</div>
      </div>
    </div>
    <div class="section-label">Risk Distribution</div>
    {_chart_bars(by_sev)}
  </div>

  <!-- ── FINDINGS TABLE ── -->
  <div class="section">
    <div class="section-title">Findings Summary</div>
    <table class="findings-table">
      <thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>URL</th><th>Status</th></tr></thead>
      <tbody>{table_rows}</tbody>
    </table>
  </div>

  <!-- ── DETAILED FINDINGS ── -->
  <div class="section">
    <div class="section-title">Detailed Findings</div>
    {cards if cards else '<p style="color:#5a6b80">No findings to display.</p>'}
  </div>

  <div class="footer">
    Generated by <strong>Catch403</strong> · {date_str} · {_h(classification)}
  </div>

</div>
</body>
</html>"""

    with open(output, "w", encoding="utf-8") as fh:
        fh.write(html_out)
    return output


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    from core.colors import bold, end, good, bad, info, run as run_col
    parser = argparse.ArgumentParser(description="Catch403 Report Generator")
    parser.add_argument("--target",    default="Target",      help="Client / target name")
    parser.add_argument("--tester",    default="",            help="Tester name")
    parser.add_argument("--scope",     default="",            help="Scope URL(s)")
    parser.add_argument("--class",     dest="classification",
                        default="CONFIDENTIAL",               help="Classification label")
    parser.add_argument("--findings",  default="",            help="JSON findings file")
    parser.add_argument("--status",    default="",
                        help="Only include findings with this status, e.g. confirmed")
    parser.add_argument("--severity",  default="",
                        help="Only include findings with these severities, e.g. critical,high")
    parser.add_argument("-o", dest="output", default="report.html")
    args = parser.parse_args()

    findings: list[dict] = []

    if args.findings:
        with open(args.findings) as fh:
            data = json.load(fh)
        findings = data if isinstance(data, list) else [data]
    else:
        # Pull from FindingTracker
        try:
            from modules.finding_tracker import FindingTracker
            db = FindingTracker()
            findings = db.query(
                status=args.status or "",
                severity=args.severity or "",
            )
            print(f"{run_col} Loaded {len(findings)} finding(s) from tracker DB")
        except Exception as e:
            print(f"{bad} Could not load from tracker: {e}")
            sys.exit(1)

    if args.severity:
        allowed = {s.strip() for s in args.severity.split(",")}
        findings = [f for f in findings if f.get("severity") in allowed]

    print(f"{run_col} Generating report: {bold}{args.target}{end} — {len(findings)} finding(s)")
    out = generate(
        findings,
        target=args.target,
        tester=args.tester,
        scope=args.scope,
        classification=args.classification,
        status_filter=args.status,
        output=args.output,
    )
    print(f"{good} Report saved → {bold}{out}{end}")


if __name__ == "__main__":
    main()
