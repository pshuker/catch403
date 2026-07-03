#!/usr/bin/python3
"""
Vulnerability Chainer — Attack Chain Discovery.

Analyses findings in the tracker and identifies combinations that form
higher-severity attack chains. The #1 gap between automated tool output
and a real pentest report.

Example chains:
  CORS misconfiguration + CSRF bypass → critical cross-origin data theft
  Open redirect + OAuth callback → account takeover
  Reflected XSS + self-XSS + CSRF → account takeover chain
  SSRF + internal metadata → cloud credential theft
  Information disclosure + weak auth → privilege escalation path

Usage:
  ../.venv/bin/python3 modules/vuln_chainer.py          # analyse all confirmed findings
  ../.venv/bin/python3 modules/vuln_chainer.py --pending # include pending findings
  ../.venv/bin/python3 modules/vuln_chainer.py --json findings.json
  ../.venv/bin/python3 modules/vuln_chainer.py -o chains.json
"""
import argparse
import json
import os
import sys
from dataclasses import dataclass, field

from core.colors import bold, end, good, bad, info, run

# ── attack chain rules ────────────────────────────────────────────────────

@dataclass
class ChainRule:
    name: str
    severity: str
    components: list[str]  # finding name substrings that must ALL be present
    description: str
    attack_narrative: str
    remediation: str
    references: list[str] = field(default_factory=list)


# The rule library — patterns of finding names that form chains
CHAIN_RULES: list[ChainRule] = [
    ChainRule(
        name="CORS + Authenticated Endpoint → Cross-Origin Data Theft",
        severity="critical",
        components=["cors", "authenticated"],
        description=(
            "An authenticated endpoint is accessible from arbitrary origins. "
            "An attacker can host malicious JavaScript that reads sensitive user data "
            "by making cross-origin requests using the victim's active session."
        ),
        attack_narrative=(
            "1. Victim visits attacker's website while logged into target.\n"
            "2. Attacker's JS calls target API endpoint cross-origin.\n"
            "3. Target's CORS policy reflects the attacker's origin.\n"
            "4. Target's API returns user data to attacker's origin.\n"
            "5. Attacker's JS reads and exfiltrates the response."
        ),
        remediation=(
            "Restrict ACAO to the exact application origin. "
            "Use an allowlist, never reflect arbitrary origins. "
            "Ensure credentials=true is only set alongside a specific allowed origin."
        ),
        references=["https://portswigger.net/web-security/cors"],
    ),
    ChainRule(
        name="CORS + CSRF Token Exposure → CSRF Bypass",
        severity="high",
        components=["cors", "csrf"],
        description=(
            "CORS misconfiguration allows an attacker to first read a CSRF token "
            "from a protected page, then replay it in a forged state-changing request."
        ),
        attack_narrative=(
            "1. Attacker reads target page cross-origin (CORS bug allows it).\n"
            "2. Attacker extracts CSRF token from the response body.\n"
            "3. Attacker forges a state-changing request with the valid CSRF token.\n"
            "4. Request succeeds, bypassing CSRF protection."
        ),
        remediation=(
            "Fix CORS policy first. Additionally, ensure CSRF tokens are tied to the "
            "session and not predictable."
        ),
        references=["https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions"],
    ),
    ChainRule(
        name="Open Redirect + OAuth/SSO → Account Takeover",
        severity="critical",
        components=["open redirect", "oauth"],
        description=(
            "An open redirect on the same domain as the OAuth callback can be used "
            "to steal authorization codes by manipulating the redirect_uri parameter."
        ),
        attack_narrative=(
            "1. Attacker discovers open redirect on target.com/redirect?url=X.\n"
            "2. Attacker crafts OAuth URL with redirect_uri=target.com/redirect?url=attacker.com.\n"
            "3. Victim authorises the app. OAuth redirects to target.com/redirect?url=attacker.com.\n"
            "4. Open redirect sends the authorization code to attacker.com in the URL.\n"
            "5. Attacker exchanges code for access token → account takeover."
        ),
        remediation=(
            "Fix open redirect: use an allowlist of redirect destinations. "
            "Validate OAuth redirect_uri exactly against a pre-registered allowlist. "
            "Never allow path or parameter overrides."
        ),
        references=["https://portswigger.net/web-security/oauth"],
    ),
    ChainRule(
        name="SSRF + Cloud Metadata → Credential Theft",
        severity="critical",
        components=["ssrf", "metadata"],
        description=(
            "SSRF allows fetching internal cloud metadata endpoints (169.254.169.254). "
            "These expose IAM credentials, granting full cloud API access."
        ),
        attack_narrative=(
            "1. SSRF vulnerability allows attacker to control a URL fetched server-side.\n"
            "2. Attacker points it at http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "3. Cloud returns IAM role credentials (key, secret, session token).\n"
            "4. Attacker uses credentials to access AWS/GCP/Azure resources directly."
        ),
        remediation=(
            "Block outbound requests to RFC-1918, loopback, and link-local ranges. "
            "Use IMDSv2 (token-required mode) on AWS. "
            "Apply URL allowlisting for any URL-fetching functionality."
        ),
        references=["https://portswigger.net/web-security/ssrf"],
    ),
    ChainRule(
        name="Reflected XSS + CSRF → Account Takeover",
        severity="critical",
        components=["xss", "csrf"],
        description=(
            "XSS can be used to steal session tokens or CSRF tokens, "
            "then forge requests on behalf of the victim."
        ),
        attack_narrative=(
            "1. Attacker sends victim a URL containing reflected XSS payload.\n"
            "2. XSS fires in victim's browser, reads session cookie or CSRF token.\n"
            "3. XSS sends stolen credentials to attacker's server.\n"
            "4. Attacker uses credentials to take over account."
        ),
        remediation=(
            "Fix XSS with proper output encoding and CSP. "
            "Use HttpOnly on session cookies so they can't be read by JS. "
            "Ensure SameSite cookie attribute prevents cross-site requests."
        ),
        references=["https://owasp.org/www-community/attacks/xss/"],
    ),
    ChainRule(
        name="Information Disclosure + Default Credentials → Full Compromise",
        severity="critical",
        components=["information disclosure", "default credential"],
        description=(
            "Version/technology disclosure combined with known default credentials "
            "provides a direct path to full access."
        ),
        attack_narrative=(
            "1. Info disclosure reveals server version (e.g. phpMyAdmin 4.5.0).\n"
            "2. CVE database confirms default credentials for this version.\n"
            "3. Attacker authenticates with default credentials.\n"
            "4. Full administrative access obtained."
        ),
        remediation=(
            "Disable server version headers. Change all default credentials immediately. "
            "Implement account lockout after N failed attempts."
        ),
        references=["https://owasp.org/www-project-top-ten/"],
    ),
    ChainRule(
        name="Subdomain Takeover + Cookie Scope → Session Hijacking",
        severity="high",
        components=["subdomain takeover", "cookie"],
        description=(
            "A dangling DNS record allows an attacker to register the subdomain. "
            "If session cookies are scoped to .target.com, they're readable from "
            "the attacker-controlled subdomain."
        ),
        attack_narrative=(
            "1. Attacker registers the dangling subdomain (e.g. staging.target.com → Heroku).\n"
            "2. Attacker deploys malicious JS on staging.target.com.\n"
            "3. Victim visits any target.com page — JS loads from staging (e.g. via CDN link).\n"
            "4. Malicious JS reads .target.com-scoped cookies.\n"
            "5. Session hijacked."
        ),
        remediation=(
            "Audit and remove unused DNS records. "
            "Use __Host- cookie prefix to restrict to exact host only. "
            "Do not scope session cookies to parent domain unless necessary."
        ),
        references=["https://portswigger.net/web-security/host-header/exploiting"],
    ),
    ChainRule(
        name="SQL Injection + User Enumeration → Credential Stuffing Path",
        severity="high",
        components=["sql injection", "user enum"],
        description=(
            "SQL injection can expose usernames and hashed passwords. "
            "User enumeration confirms active accounts. Together they enable "
            "targeted credential attacks."
        ),
        attack_narrative=(
            "1. SQLi extracts user table: usernames + password hashes.\n"
            "2. User enum confirms which accounts are active.\n"
            "3. Attacker cracks hashes offline (weak hashes) or uses them in stuffing attacks.\n"
            "4. Compromised credentials reused across services."
        ),
        remediation=(
            "Use parameterised queries (eliminate SQLi root cause). "
            "Hash passwords with bcrypt/argon2. "
            "Return identical responses for valid/invalid usernames."
        ),
        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
    ),
    ChainRule(
        name="CORS + Stored XSS → Wormable XSS",
        severity="critical",
        components=["cors", "stored xss"],
        description=(
            "Stored XSS combined with permissive CORS enables cross-origin exfiltration "
            "of data from all users who view the infected page."
        ),
        attack_narrative=(
            "1. Attacker injects stored XSS payload into a shared resource.\n"
            "2. Every victim who views the page executes the payload.\n"
            "3. XSS calls authenticated API endpoints (CORS allows it).\n"
            "4. Victim data exfiltrated to attacker cross-origin."
        ),
        remediation=(
            "Fix stored XSS with output encoding and CSP. Fix CORS policy. "
            "Implement SameSite=Strict on session cookies."
        ),
        references=["https://portswigger.net/web-security/cross-site-scripting"],
    ),
    ChainRule(
        name="JWT Algorithm Confusion + Privilege Escalation",
        severity="critical",
        components=["jwt", "privilege"],
        description=(
            "JWT algorithm confusion (RS256 → HS256) allows signing arbitrary tokens "
            "with the public key, enabling role/privilege escalation."
        ),
        attack_narrative=(
            "1. Server uses RS256; public key is accessible (JWKS endpoint or leaked).\n"
            "2. Attacker obtains public key and re-signs a modified JWT with HS256.\n"
            "3. Modified JWT contains elevated role (admin=true, role=superuser).\n"
            "4. Server validates HMAC signature using public key as the secret → accepts token.\n"
            "5. Attacker has admin access."
        ),
        remediation=(
            "Explicitly specify allowed algorithms server-side (never auto-detect). "
            "Reject 'none' algorithm. Use a JWT library that enforces algorithm pinning."
        ),
        references=["https://portswigger.net/web-security/jwt/algorithm-confusion"],
    ),
    ChainRule(
        name="IDOR + Sensitive Data Exposure → Mass Data Breach",
        severity="critical",
        components=["idor", "sensitive data"],
        description=(
            "IDOR allows enumeration of all user records. Combined with sensitive "
            "data exposure in those records, this enables mass data exfiltration."
        ),
        attack_narrative=(
            "1. IDOR bug: /api/users/{id} returns any user's profile regardless of auth.\n"
            "2. Attacker enumerates all IDs (1 to N).\n"
            "3. Each response contains PII: names, emails, dates of birth, SSNs.\n"
            "4. Full user database exfiltrated."
        ),
        remediation=(
            "Implement object-level authorisation on every API endpoint. "
            "Verify object ownership before returning data. "
            "Use non-enumerable (random) IDs. Minimise data returned per response."
        ),
        references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
    ),
    ChainRule(
        name="File Upload + SSRF → Internal Network Pivot",
        severity="high",
        components=["upload", "ssrf"],
        description=(
            "A file upload that triggers server-side processing (e.g. image resize, "
            "PDF generation) can be combined with SSRF via crafted file contents."
        ),
        attack_narrative=(
            "1. Attacker uploads a specially crafted file (SVG/PDF/DOCX).\n"
            "2. Server processes the file server-side (Imagemagick, wkhtmltopdf, LibreOffice).\n"
            "3. Malicious file content triggers an outbound HTTP request to an internal host.\n"
            "4. Server fetches internal resource (SSRF via file upload)."
        ),
        remediation=(
            "Sandboxed file processing environment with no network access. "
            "Disable external entity resolution in all file parsers. "
            "Use content-type validation and magic-byte checking, not filename extension."
        ),
        references=["https://portswigger.net/web-security/file-upload"],
    ),
]


# ── matching logic ─────────────────────────────────────────────────────────

def _finding_name_lower(f: dict) -> str:
    return (f.get("name", "") + " " + f.get("detail", "")).lower()


def _matches_rule(findings: list[dict], rule: ChainRule) -> tuple[bool, list[dict]]:
    """
    Returns (matched, matching_findings).
    A rule matches if all component substrings appear in at least one finding each.
    """
    matched_findings = []
    for component in rule.components:
        comp_lower = component.lower()
        matches = [f for f in findings if comp_lower in _finding_name_lower(f)]
        if not matches:
            return False, []
        matched_findings.extend(matches)
    return True, matched_findings


def analyse(findings: list[dict]) -> list[dict]:
    """
    Analyse a list of findings for attack chain patterns.
    Returns list of chain findings (high/critical severity).
    """
    chains: list[dict] = []

    for rule in CHAIN_RULES:
        matched, involved_findings = _matches_rule(findings, rule)
        if matched:
            urls = list({f.get("url", "") for f in involved_findings if f.get("url")})
            chains.append({
                "name":             rule.name,
                "severity":         rule.severity,
                "type":             "attack_chain",
                "detail":           rule.description,
                "attack_narrative": rule.attack_narrative,
                "remediation":      rule.remediation,
                "references":       rule.references,
                "component_count":  len(rule.components),
                "involved_findings": [f.get("name", "") for f in involved_findings],
                "urls":             urls,
            })

    return chains


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Catch403 Vulnerability Chainer — Attack Chain Discovery"
    )
    parser.add_argument("--pending",  action="store_true",
                        help="Include pending findings (default: confirmed only)")
    parser.add_argument("--json",     metavar="FILE",
                        help="Load findings from JSON file instead of tracker")
    parser.add_argument("--rules",    action="store_true",
                        help="List all chain detection rules")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    if args.rules:
        print(f"\n{bold}Attack Chain Rules ({len(CHAIN_RULES)} total){end}\n")
        for i, rule in enumerate(CHAIN_RULES, 1):
            sev_col = "\033[91m" if rule.severity == "critical" else "\033[33m"
            print(f"  {i:>2}. {sev_col}{rule.severity.upper()}{end}  {rule.name}")
            print(f"       Requires: {' + '.join(f'[{c}]' for c in rule.components)}")
        print()
        return

    # Load findings
    findings: list[dict] = []
    if args.json:
        with open(args.json) as fh:
            findings = json.load(fh)
        if isinstance(findings, dict):
            findings = [findings]
    else:
        try:
            from modules.finding_tracker import FindingTracker, CONFIRMED, PENDING
            db = FindingTracker()
            statuses = [CONFIRMED]
            if args.pending:
                statuses.append(PENDING)
            findings = db.query(status=statuses)
        except Exception as e:
            print(f"{bad} Failed to load findings from tracker: {e}")
            sys.exit(1)

    if not findings:
        print(f"{info} No findings to analyse")
        return

    print(f"{run} Analysing {len(findings)} finding(s) for attack chains...")
    print(f"{info} Testing {len(CHAIN_RULES)} chain rules\n")

    chains = analyse(findings)

    if not chains:
        print(f"{info} No attack chains detected from current finding set.")
        print(f"     Individual findings may still be significant — check the tracker.")
    else:
        print(f"{good} {len(chains)} attack chain(s) identified:\n")
        for chain in chains:
            sev = chain["severity"]
            col = "\033[91m" if sev == "critical" else "\033[33m"
            print(f"  {col}{'[' + sev.upper() + ']'}\033[0m {bold}{chain['name']}{end}")
            print(f"  {chain['detail']}")
            print(f"\n  Components: {', '.join(chain['involved_findings'][:4])}")
            print(f"\n  Attack Narrative:")
            for line in chain["attack_narrative"].splitlines():
                print(f"    {line}")
            print(f"\n  Remediation: {chain['remediation'][:120]}")
            if chain["references"]:
                print(f"  References:  {chain['references'][0]}")
            print()

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(chains, fh, indent=2)
        print(f"{good} Chains saved to {args.output}")


if __name__ == "__main__":
    main()
