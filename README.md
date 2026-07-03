# Catch403

A Python-native web application security testing platform. Intercept, inspect, and attack HTTP/HTTPS traffic through a dark-themed browser UI — no Java, no licence fees, no rate-throttled Intruder.

![Python](https://img.shields.io/badge/python-3.11+-blue) ![Tests](https://img.shields.io/badge/tests-170%20passing-4ec9a5) ![Modules](https://img.shields.io/badge/modules-50-4c8dff) ![License](https://img.shields.io/badge/license-MIT%20%2B%20Responsible%20Use-red)

---

## What it does

Catch403 covers the full web application penetration testing workflow — from interception and recon through active exploitation, finding management, AI-assisted triage, and professional report generation.

| Layer | Coverage |
|---|---|
| **Interception** | MITM proxy with HTTPS (cert auto-generated), request history, scope control |
| **Recon** | Spider, content discovery, fingerprinting, DNS rebinding, subdomain enum |
| **Injection** | SQLi, NoSQLi, CMDi, SSTI, XXE, SSRF, CRLF, XSS, LDAP, prototype pollution |
| **Auth** | JWT attacks, OAuth/OIDC testing, CSRF PoC, user enumeration, default creds, IDOR/BOLA |
| **Protocol** | HTTP request smuggling, TLS/SSL scanner, CORS, GraphQL |
| **File/Upload** | Upload scanner, path traversal, XXE via SVG |
| **Passive** | Secret/key detection, security headers, RetireJS, sensitive data patterns, insecure transmission |
| **Workflow** | Finding tracker (SQLite), AI triage (Claude), HTML report generation, CI/CD runner with baseline diff, attack chain discovery |
| **Wordlists** | 19 curated SecLists files (paths, params, payloads, usernames, LFI, SSTI, SQLi, XSS, XXE…) |
| **Integrated tools** | sqlmap (GitHub HEAD via submodule), commix (GitHub HEAD), wapiti3 |

---

## Quick start

```bash
git clone --recurse-submodules https://github.com/pshuker/catch403.git
cd catch403
python3 -m venv .venv
.venv/bin/pip install requests beautifulsoup4 lxml tabulate cryptography anthropic wapiti3

# Start web UI
cd catch403
../.venv/bin/python3 web/server.py
# → http://localhost:8888
```

### HTTPS interception

```bash
../.venv/bin/python3 modules/intercepting_proxy.py   # starts on :8080
# Import CA cert into browser: ~/.catch403/ca/ca.crt
# Set browser proxy: localhost:8080
```

---

## Module reference

### Proxy & Traffic

| Module | What it does |
|---|---|
| `intercepting_proxy.py` | Full MITM proxy. Intercepts HTTP + HTTPS, auto-generates CA cert, request/response editing |
| `logger_plus.py` | SQLite traffic log (`~/.catch403/traffic.db`). Query by host, method, status, body content |
| `auto_repeater.py` | Automatically resends matching requests with modified headers/params |
| `scope.py` | Include/exclude rules (domain, path, regex). Feeds all other modules |
| `comparer.py` | Diff two requests or responses side-by-side |
| `response_beautifier.py` | Auto-pretty-print JSON, HTML, XML responses |

### Recon & Discovery

| Module | What it does |
|---|---|
| `spider.py` | Crawl a target, extract all links, forms, JS endpoints |
| `content_discovery.py` | Wordlist-driven path bruteforce. Swappable `-w` flag (seclists-paths default) |
| `fingerprint.py` | Detect server, CMS, framework, JS libraries from headers and body. 18 recon paths checked |
| `dns_rebinding.py` | Generate DNS rebinding attack pages and payloads |
| `param_miner.py` | Discover hidden parameters via wordlist injection + response diffing |
| `secret_finder.py` | Regex scan responses for API keys, tokens, credentials (AWS, GCP, Stripe, JWT, etc.) |

### Injection & Active Scanning

| Module | What it does |
|---|---|
| `active_scan.py` | Runs all active scan checks against a target |
| `sqlmap_scanner.py` | Wraps sqlmap (GitHub HEAD, `vendor/sqlmap`). Prefers vendor → pip → PATH |
| `commix_scanner.py` | Wraps commix (GitHub HEAD, `vendor/commix`). All techniques: classic, eval, time-based, file |
| `wapiti_scanner.py` | Wraps wapiti3. JSON report parsed into standard findings |
| `nosql_scanner.py` | MongoDB operator injection (`$gt`, `$ne`, `$where`), auth bypass, blind boolean, CouchDB probes |
| `ldap_scanner.py` | Error-based, 11 auth bypass payloads, blind boolean LDAP injection |
| `ssrf_scanner.py` | Cloud metadata (AWS/GCP/Azure/DO), internal probes, file:// dict:// gopher://. IP bypass encodings. OOB support |
| `ssti_scanner.py` | Jinja2, Twig, Freemarker, Mako, Smarty, Velocity, ERB, OGNL. Math probes + RCE confirmation per engine |
| `xxe_scanner.py` | Classic file read, XInclude, error-based blind, OOB parameter entity, SSRF via XXE, SVG upload |
| `crlf_scanner.py` | Header injection via raw / URL-encoded / double-encoded CRLF. Set-Cookie, Location, XSS via response split |
| `open_redirect.py` | 23 bypass techniques: scheme-relative, `javascript:` URI, `@` authority confusion, whitelist bypass |
| `prototype_pollution.py` | `__proto__`, `constructor.prototype`, nested merge. Query string and JSON body. Canary-reflection detection |
| `cors_scanner.py` | Wildcard, origin reflection, null origin, subdomain injection, OPTIONS pre-flight bypass |
| `smuggler.py` | CL.TE / TE.CL HTTP request smuggling probes |
| `graphql_raider.py` | Introspection, field suggestions, batch queries, nested query depth |
| `upload_scanner.py` | Polyglot uploads, extension bypass, MIME confusion, XXE via SVG/XML |
| `bypass_403.py` | 403/401 bypass: path manipulation, header injection, HTTP verb tampering |

### Authentication & Session

| Module | What it does |
|---|---|
| `jwt_analyser.py` | `alg:none`, RS256→HS256 confusion, weak secret bruteforce, `kid` injection, expired token acceptance |
| `oauth_tester.py` | Open `redirect_uri`, state CSRF, token leakage via Referer, implicit flow risks |
| `csrf_poc.py` | Auto-generate CSRF PoC HTML from any request |
| `user_enum.py` | Timing-based, response-based, default credential testing. Swappable wordlist (`-w`) |
| `autorize.py` | Replay every request with a lower-privileged session to detect broken auth |
| `idor_scanner.py` | Dual-session swap (User A requests → User B token). Response diffing by size ratio. Numeric ID enumeration. Secondary endpoints (`/export`, `/download`, `/pdf`…) |
| `cookie_analyser.py` | HttpOnly, Secure, SameSite flags; domain scope; short token detection; session fixation |
| `sequencer.py` | Token entropy analysis for session tokens and CSRF tokens |

### Passive Analysis

| Module | What it does |
|---|---|
| `security_headers.py` | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| `ssl_tls_scanner.py` | TLS 1.0/1.1, weak ciphers, cert expiry, self-signed certs, CN mismatch, HSTS |
| `sensitive_data.py` | PII in responses: credit cards, SSNs, emails, phone numbers |
| `insecure_transmission.py` | Mixed-content, HTTP endpoints, unencrypted form submissions |
| `retire_js.py` | Detect outdated JavaScript libraries with known CVEs |

### Workflow & Reporting

| Module | What it does |
|---|---|
| `finding_tracker.py` | SQLite triage DB (`~/.catch403/findings.db`). Confirm / reject / wont_fix / fixed. Notes, tags, JSON import/export |
| `report_generator.py` | Self-contained HTML pentest report. Cover page, executive summary, severity chart, finding cards with evidence, curl commands, remediation. Print-ready CSS |
| `ai_assist.py` | Claude API (claude-sonnet-4-6). Analyse request/response pairs, explain findings, suggest payloads, draft report sections, batch AI-triage pending findings |
| `vuln_chainer.py` | 12-rule attack chain engine. Maps individual findings to compound chains: CORS+CSRF, Open Redirect+OAuth, SSRF+Metadata, IDOR+Data Exposure, XSS+CSRF, JWT+Privilege, and more |
| `cicd_runner.py` | Pipeline-native scanner. Saves baseline on first run, diffs on subsequent (new findings only). SARIF for GitHub Code Scanning. PR comment posting. Severity threshold exit codes. Profiles: quick / standard / full / api |
| `oob_helper.py` | Burp Collaborator alternative using ProjectDiscovery interactsh (free). Register session, per-test canary tokens, poll for DNS/HTTP interactions, correlate back to payload |

### Utilities

| Module | What it does |
|---|---|
| `hackvertor.py` | Encode/decode: URL, HTML, Base64, hex, Unicode, JWT, hashing |
| `hash_id.py` | Identify hash type (MD5, SHA-1/256/512, bcrypt, argon2, JWT…) and attempt cracking |
| `intruder.py` | Unthrottled fuzzer — no 1-req/s Community Edition limit |
| `turbo_intruder.py` | High-concurrency asyncio request engine for race condition testing |
| `wordlists.py` | Central wordlist registry. 19 files, 9 categories. Swappable via `-w` across all modules |

---

## Wordlists

All curated to ≤10 000 lines — no 1.9 GB clone needed.

```
wordlists/
  seclists-paths.txt       4 750 paths
  seclists-api.txt           295 API paths
  seclists-subdomains.txt  5 000 subdomains
  seclists-lfi.txt           930 LFI payloads
  seclists-cmdi.txt        3 000 command injection payloads
  seclists-sqli.txt          268 SQLi payloads
  seclists-xss.txt           113 XSS payloads
  seclists-xxe.txt            51 XXE payloads
  seclists-ssti.txt           11 SSTI probe strings
  seclists-ldap.txt           26 LDAP payloads
  + usernames, passwords, params, subdomains (curated)
```

Swap wordlists on any supporting module:

```bash
python3 modules/content_discovery.py -u https://target.com -w seclists-api
python3 modules/user_enum.py -u https://target.com/login -w seclists-usernames
python3 modules/wordlists.py --list        # all available wordlists
python3 modules/wordlists.py --categories  # by category
```

---

## Integrated external tools

```bash
# Add submodules (included if cloned with --recurse-submodules)
git submodule update --init --recursive
```

| Tool | Source | Integration |
|---|---|---|
| **sqlmap** | `vendor/sqlmap` (GitHub HEAD) | `--batch` mode, output parsed into standard findings |
| **commix** | `vendor/commix` (GitHub HEAD) | All injection techniques, output parsed into findings |
| **wapiti3** | pip (`wapiti3`) | `--format json` output mapped to standard severity levels |

---

## Workflow example

```bash
# 1. Fingerprint the target
python3 modules/fingerprint.py -u https://target.com

# 2. Discover content
python3 modules/content_discovery.py -u https://target.com -w seclists-paths

# 3. Active scanning
python3 modules/ssrf_scanner.py -u "https://target.com/fetch?url=test"
python3 modules/ssti_scanner.py -u "https://target.com/render?name=test"
python3 modules/cors_scanner.py -u https://target.com/api/data
python3 modules/jwt_analyser.py --token eyJ...
python3 modules/idor_scanner.py -u https://target.com/api/users/42 \
    --session-a "Authorization: Bearer TOKEN_A" \
    --session-b "Authorization: Bearer TOKEN_B"

# 4. Triage findings
python3 modules/finding_tracker.py --list
python3 modules/finding_tracker.py --confirm 3 --note "Verified in prod"

# 5. AI triage
python3 modules/ai_assist.py --set-key sk-ant-...
python3 modules/ai_assist.py --triage

# 6. Discover attack chains
python3 modules/vuln_chainer.py

# 7. Generate report
python3 modules/report_generator.py -o report.html --target "target.com" --tester "Your Name"
```

---

## CI/CD integration

```bash
# Save baseline (first run)
python3 catch403/modules/cicd_runner.py -u https://staging.myapp.com --save-baseline

# Subsequent runs — new findings only, fails on high+
python3 catch403/modules/cicd_runner.py -u https://staging.myapp.com \
    --profile standard --severity high --sarif results.sarif

# GitHub Actions with PR comment
python3 catch403/modules/cicd_runner.py -u $TARGET_URL \
    --github-token $GITHUB_TOKEN --pr $PR_NUMBER --repo owner/repo
```

---

## OOB / Blind detection

```bash
# Register a free interactsh session (no account needed)
python3 modules/oob_helper.py --start

# Generate a canary URL for a specific test
python3 modules/oob_helper.py --generate --token ssrf-test

# Poll for interactions
python3 modules/oob_helper.py --poll

# Quick canary (no session required)
python3 modules/oob_helper.py --canary
```

---

## Attack chain discovery

```bash
python3 modules/vuln_chainer.py            # analyse confirmed findings in tracker
python3 modules/vuln_chainer.py --rules    # list all 12 chain detection rules
python3 modules/vuln_chainer.py --json confirmed.json -o chains.json
```

Detected chains include: CORS+CSRF, Open Redirect+OAuth → account takeover, SSRF+Cloud Metadata → credential theft, IDOR+Sensitive Data → mass breach, JWT algorithm confusion+Privilege → admin access, SQLi+User Enumeration → credential pipeline.

---

## AI Assist

Requires an [Anthropic API key](https://console.anthropic.com).

```bash
python3 modules/ai_assist.py --set-key sk-ant-...
python3 modules/ai_assist.py --analyse --request req.txt --response resp.txt
python3 modules/ai_assist.py --explain --finding-id 3
python3 modules/ai_assist.py --suggest "SQLi in login form, MySQL, WAF present"
python3 modules/ai_assist.py --report --finding-id 3
python3 modules/ai_assist.py --triage
python3 modules/ai_assist.py --ask "How do I exploit HTTP/2 request tunnelling?"
```

---

## Tests

```bash
cd catch403
../.venv/bin/python3 tests.py
../.venv/bin/python3 tests_modules.py
../.venv/bin/python3 tests_new_modules.py   # 170 tests covering all new modules
```

---

## Project layout

```
catch403/                    ← git repo root
├── catch403/                ← Python package
│   ├── core/                # Flow model, module pipeline, ZAP bridge
│   ├── modules/             # 50 security modules
│   ├── Burpee/              # Burp .xml / .burp file parser
│   └── web/
│       ├── server.py        # HTTP API (port 8888)
│       └── index.html       # Single-file dark-themed UI
├── docs/                    # CLI reference and guides
├── wordlists/               # 19 curated payload/path/username lists
└── vendor/
    ├── sqlmap/              # sqlmapproject/sqlmap @ HEAD
    └── commix/              # commixproject/commix @ HEAD
```

---

## Docs

- [CLI Reference](docs/cli_reference.md)
- [Writing a Module](catch403/MODULE_GUIDE.md)

---

## Legal

**Catch403 is an offensive security tool. Use it only against systems you own or have received explicit, written authorisation to test.**

Unauthorised use against systems you do not own or do not have permission to test is illegal under the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and equivalent legislation in most jurisdictions worldwide. Penalties can include criminal prosecution, fines, and imprisonment.

**By using this tool you confirm that:**

- You have written permission from the system owner before running any scan or test
- You are operating within the agreed scope of an authorised engagement
- You accept full legal and ethical responsibility for how you use it
- You will not use it to attack systems you do not have permission to test

This software is provided for authorised penetration testing, security research, CTF competitions, and educational use only. The author accepts no liability for misuse or any damage caused by using this tool outside of those contexts.

If you are unsure whether you have permission — you do not have permission.
