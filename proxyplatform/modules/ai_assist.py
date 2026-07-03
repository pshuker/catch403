#!/usr/bin/python3
"""
AI Assist — Claude-powered security analysis for Catch403.

Uses the Anthropic API (claude-sonnet-4-6) to:
  - Analyse HTTP request/response pairs for vulnerabilities
  - Explain findings in plain English with impact and remediation
  - Suggest payloads tailored to a specific target and context
  - Draft pentest report paragraphs from a finding
  - Answer free-form security questions

API key: set ANTHROPIC_API_KEY env var, or store in ~/.proxyplatform/config.json

Usage:
  ../.venv/bin/python3 modules/ai_assist.py --analyse --request req.txt --response resp.txt
  ../.venv/bin/python3 modules/ai_assist.py --explain --finding-id 3
  ../.venv/bin/python3 modules/ai_assist.py --suggest "SQLi in login form, MySQL backend"
  ../.venv/bin/python3 modules/ai_assist.py --report --finding-id 3
  ../.venv/bin/python3 modules/ai_assist.py --ask "What does X-Content-Type-Options do?"
  ../.venv/bin/python3 modules/ai_assist.py --triage          # AI triage all pending findings
"""
import argparse
import json
import os
import sys

from core.colors import bold, end, good, bad, info, run

_CONFIG_PATH = os.path.expanduser("~/.proxyplatform/config.json")
MODEL        = "claude-sonnet-4-6"

_SYSTEM = """You are an expert web application penetration tester and security researcher
with deep knowledge of OWASP Top 10, CVE databases, exploit techniques, and secure
development practices.

You assist security professionals during authorised penetration tests.
Give direct, technical, actionable answers. When analysing HTTP traffic:
- Identify vulnerabilities precisely (name, CWE, CVSS estimate)
- Explain the attack vector and impact clearly
- Suggest specific, working payloads where relevant
- Provide concrete remediation steps
- Reference OWASP, CVE, or PortSwigger where helpful

Be thorough and specific — the user is a security professional, not a beginner.
"""


# ── API key management ─────────────────────────────────────────────────────

def _load_api_key() -> str:
    # 1. env var
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if key:
        return key
    # 2. config file
    if os.path.isfile(_CONFIG_PATH):
        try:
            with open(_CONFIG_PATH) as fh:
                cfg = json.load(fh)
            key = cfg.get("anthropic_api_key", "")
            if key:
                return key
        except (json.JSONDecodeError, OSError):
            pass
    return ""


def save_api_key(key: str):
    os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)
    cfg = {}
    if os.path.isfile(_CONFIG_PATH):
        try:
            with open(_CONFIG_PATH) as fh:
                cfg = json.load(fh)
        except Exception:
            pass
    cfg["anthropic_api_key"] = key
    with open(_CONFIG_PATH, "w") as fh:
        json.dump(cfg, fh, indent=2)
    os.chmod(_CONFIG_PATH, 0o600)


def _client():
    try:
        import anthropic
    except ImportError:
        raise RuntimeError("pip install anthropic")
    key = _load_api_key()
    if not key:
        raise RuntimeError(
            "No Anthropic API key found.\n"
            "  Option A: export ANTHROPIC_API_KEY=sk-ant-...\n"
            "  Option B: python3 modules/ai_assist.py --set-key sk-ant-..."
        )
    import anthropic as _anthropic
    return _anthropic.Anthropic(api_key=key)


# ── core functions ─────────────────────────────────────────────────────────

def _ask_claude(prompt: str, *, stream: bool = True) -> str:
    client = _client()
    if stream:
        collected = []
        with client.messages.stream(
            model=MODEL,
            max_tokens=4096,
            system=_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        ) as s:
            for text in s.text_stream:
                print(text, end="", flush=True)
                collected.append(text)
        print()
        return "".join(collected)
    else:
        msg = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text


def analyse(request: str, response: str) -> str:
    """Analyse a request/response pair for vulnerabilities."""
    prompt = f"""Analyse this HTTP exchange for security vulnerabilities.

For each issue found:
1. Name and CWE
2. Severity (Critical/High/Medium/Low) with brief CVSS justification
3. Exact evidence from the request/response below
4. Working proof-of-concept payload or next step
5. Remediation

--- REQUEST ---
{request[:8000]}

--- RESPONSE ---
{response[:8000]}

If no vulnerabilities are found, explain why and suggest further tests."""
    return _ask_claude(prompt)


def explain(finding: dict) -> str:
    """Explain a finding in plain English with full impact and remediation."""
    prompt = f"""Explain this security finding to a technical audience.

Finding:
{json.dumps(finding, indent=2)}

Provide:
1. Plain-English explanation of what the vulnerability is and why it exists
2. Step-by-step attack scenario showing real-world impact
3. CVSS v3.1 score with vector string
4. Affected CWE
5. Specific remediation code or config example
6. OWASP or CVE references"""
    return _ask_claude(prompt)


def suggest_payloads(context: str) -> str:
    """Suggest targeted payloads for a given context."""
    prompt = f"""Generate targeted security testing payloads for this context:

{context}

Provide:
1. 10-15 specific payloads ordered by likelihood of success
2. For each payload: what it tests, expected response if vulnerable
3. Bypass variants for common WAF rules
4. Manual verification steps"""
    return _ask_claude(prompt)


def draft_report(finding: dict) -> str:
    """Draft a professional pentest report paragraph for a finding."""
    prompt = f"""Write a professional penetration test report section for this finding.

Finding data:
{json.dumps(finding, indent=2)}

Format:
## [Finding Name] — [Severity]

**Risk:** [one sentence]

**Description:**
[2-3 paragraphs explaining the issue, how it was found, and technical detail]

**Impact:**
[Business and technical impact]

**Evidence:**
[Reference the evidence in the finding data]

**Remediation:**
[Specific, actionable steps with code examples where possible]

**References:**
[OWASP, CWE, CVE links]

Write in formal, concise penetration test report style."""
    return _ask_claude(prompt)


def triage_finding(finding: dict) -> dict:
    """AI-assisted triage: suggest status, severity, and notes."""
    prompt = f"""Triage this security finding and return a JSON object.

Finding:
{json.dumps(finding, indent=2)}

Return ONLY valid JSON with these fields:
{{
  "suggested_status": "confirmed|false_positive|wont_fix|pending",
  "suggested_severity": "critical|high|medium|low|info",
  "confidence": "high|medium|low",
  "reasoning": "one sentence",
  "notes": "brief analyst note for the finding tracker"
}}"""
    result = _ask_claude(prompt, stream=False)
    try:
        # Extract JSON from response
        import re
        m = re.search(r'\{.*\}', result, re.DOTALL)
        if m:
            return json.loads(m.group())
    except Exception:
        pass
    return {"reasoning": result, "notes": result}


def ask(question: str) -> str:
    """Free-form security question."""
    return _ask_claude(question)


# ── batch triage ───────────────────────────────────────────────────────────

def triage_all_pending(db_path: str = "") -> int:
    """Run AI triage on all pending findings in the tracker."""
    from modules.finding_tracker import FindingTracker, PENDING
    db = FindingTracker(db_path) if db_path else FindingTracker()
    pending = db.query(status=PENDING)
    if not pending:
        print(f"{info} No pending findings to triage")
        return 0

    print(f"{run} AI triage of {len(pending)} pending finding(s) via {MODEL}\n")
    triaged = 0
    for f in pending:
        fid = f["id"]
        print(f"{info} [{fid}] {f['name']} ({f['severity']})")
        try:
            result = triage_finding(f)
            status    = result.get("suggested_status", PENDING)
            severity  = result.get("suggested_severity", f["severity"])
            notes     = result.get("notes", result.get("reasoning", ""))
            confidence = result.get("confidence", "")
            print(f"     → {status} ({severity}) [{confidence} confidence]")
            print(f"       {notes[:120]}")
            db.update_status(fid, status, notes)
            triaged += 1
        except Exception as e:
            print(f"     {bad} Error: {e}")
        print()

    print(f"{good} Triaged {triaged}/{len(pending)} finding(s)")
    return triaged


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Catch403 AI Assist — Claude-powered security analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Analyse an HTTP exchange
  ai_assist.py --analyse --request req.txt --response resp.txt

  # Explain finding #3 from the tracker
  ai_assist.py --explain --finding-id 3

  # Suggest payloads
  ai_assist.py --suggest "SSRF via URL parameter, internal AWS metadata"

  # Draft report section for finding #3
  ai_assist.py --report --finding-id 3

  # AI triage all pending findings
  ai_assist.py --triage

  # Free-form question
  ai_assist.py --ask "How do I exploit HTTP request smuggling on nginx+gunicorn?"

  # Store API key
  ai_assist.py --set-key sk-ant-..."""
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyse",    action="store_true", help="Analyse request/response")
    mode.add_argument("--explain",    action="store_true", help="Explain a finding")
    mode.add_argument("--suggest",    metavar="CONTEXT",   help="Suggest payloads for context")
    mode.add_argument("--report",     action="store_true", help="Draft report section for a finding")
    mode.add_argument("--triage",     action="store_true", help="AI triage all pending findings")
    mode.add_argument("--ask",        metavar="QUESTION",  help="Free-form security question")
    mode.add_argument("--set-key",    metavar="KEY",       help="Save Anthropic API key to config")

    parser.add_argument("--request",    metavar="FILE", help="HTTP request file (for --analyse)")
    parser.add_argument("--response",   metavar="FILE", help="HTTP response file (for --analyse)")
    parser.add_argument("--request-text",  default="",  help="Raw request text (for --analyse)")
    parser.add_argument("--response-text", default="",  help="Raw response text (for --analyse)")
    parser.add_argument("--finding-id", type=int, metavar="ID", help="Finding ID from tracker")
    parser.add_argument("--finding",    metavar="FILE", help="Finding JSON file")
    parser.add_argument("-o", dest="output", default="", help="Save response to file")
    args = parser.parse_args()

    # Store key
    if args.set_key:
        save_api_key(args.set_key)
        print(f"{good} API key saved to {_CONFIG_PATH}")
        return

    # Helper to load finding
    def _load_finding() -> dict:
        if args.finding_id:
            from modules.finding_tracker import FindingTracker
            db = FindingTracker()
            f = db.get(args.finding_id)
            if not f:
                print(f"{bad} Finding #{args.finding_id} not found in tracker")
                sys.exit(1)
            return f
        if args.finding:
            with open(args.finding) as fh:
                return json.load(fh)
        print(f"{bad} Provide --finding-id ID or --finding FILE")
        sys.exit(1)

    try:
        result = ""

        if args.analyse:
            req = args.request_text
            resp = args.response_text
            if args.request:
                with open(args.request) as fh: req = fh.read()
            if args.response:
                with open(args.response) as fh: resp = fh.read()
            if not req:
                print(f"{bad} Provide --request FILE or --request-text TEXT")
                sys.exit(1)
            print(f"{run} Analysing HTTP exchange with {bold}{MODEL}{end}\n")
            result = analyse(req, resp)

        elif args.explain:
            f = _load_finding()
            print(f"{run} Explaining: {bold}{f.get('name','')}{end}\n")
            result = explain(f)

        elif args.suggest:
            print(f"{run} Suggesting payloads for: {bold}{args.suggest[:80]}{end}\n")
            result = suggest_payloads(args.suggest)

        elif args.report:
            f = _load_finding()
            print(f"{run} Drafting report section for: {bold}{f.get('name','')}{end}\n")
            result = draft_report(f)

        elif args.triage:
            triage_all_pending()
            return

        elif args.ask:
            print(f"{run} Asking Claude: {bold}{args.ask[:80]}{end}\n")
            result = ask(args.ask)

        if result and args.output:
            with open(args.output, "w") as fh:
                fh.write(result)
            print(f"\n{good} Saved to {args.output}")

    except RuntimeError as e:
        print(f"{bad} {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n(interrupted)")


if __name__ == "__main__":
    main()
