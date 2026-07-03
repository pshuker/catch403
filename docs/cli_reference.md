# CLI Reference

All commands run from the `catch403/` directory using the project venv.

```bash
cd catch403
# prefix every command below with:
../.venv/bin/python3 modules/<module>.py [flags]
```

---

## Web UI

```bash
../.venv/bin/python3 web/server.py [--port 8888] [--host 127.0.0.1]
# → http://localhost:8888
```

---

## Proxy & Traffic

### Intercepting Proxy

```bash
../.venv/bin/python3 modules/intercepting_proxy.py
../.venv/bin/python3 modules/intercepting_proxy.py --port 8080 --host 127.0.0.1
../.venv/bin/python3 modules/intercepting_proxy.py --scope target.com
../.venv/bin/python3 modules/intercepting_proxy.py --ca-info
# CA cert: ~/.catch403/ca/ca.crt  — import into browser for HTTPS interception
```

### Traffic Logger

```bash
../.venv/bin/python3 modules/logger_plus.py --list
../.venv/bin/python3 modules/logger_plus.py --list --host target.com --status 200 --limit 100
../.venv/bin/python3 modules/logger_plus.py --get <id>
../.venv/bin/python3 modules/logger_plus.py --export traffic.json
../.venv/bin/python3 modules/logger_plus.py --export traffic.csv
../.venv/bin/python3 modules/logger_plus.py --export traffic.xml   # Burp XML format
../.venv/bin/python3 modules/logger_plus.py --clear
../.venv/bin/python3 modules/logger_plus.py --count
```

### Scope

```bash
../.venv/bin/python3 modules/scope.py add target.com
../.venv/bin/python3 modules/scope.py add staging.target.com --exclude
../.venv/bin/python3 modules/scope.py list
../.venv/bin/python3 modules/scope.py remove 0
../.venv/bin/python3 modules/scope.py check https://target.com/login
../.venv/bin/python3 modules/scope.py clear
```

### Auto Repeater

```bash
../.venv/bin/python3 modules/auto_repeater.py --demo
../.venv/bin/python3 modules/auto_repeater.py --rules my_rules.json
../.venv/bin/python3 modules/auto_repeater.py --export rules.json
```

### Comparer

```bash
../.venv/bin/python3 modules/comparer.py a.txt b.txt
../.venv/bin/python3 modules/comparer.py a.txt b.txt --similarity
```

---

## Recon & Discovery

### Spider

```bash
../.venv/bin/python3 modules/spider.py -u https://target.com
../.venv/bin/python3 modules/spider.py -u https://target.com --depth 5 --delay 0.5
```

### Content Discovery

```bash
../.venv/bin/python3 modules/content_discovery.py -u https://target.com
../.venv/bin/python3 modules/content_discovery.py -u https://target.com -w seclists-api
../.venv/bin/python3 modules/content_discovery.py -u https://target.com -w wordlist.txt -e php,txt,bak -t 40
../.venv/bin/python3 modules/content_discovery.py -u https://target.com --status 200,301,403 -o results.json
```

### Fingerprint

```bash
../.venv/bin/python3 modules/fingerprint.py -u https://target.com
../.venv/bin/python3 modules/fingerprint.py -u https://target.com -o findings.json
# Detects: server, CMS, framework, JS libraries. Checks 18 recon paths (/.env, /.git/HEAD, etc.)
```

### Param Miner

```bash
../.venv/bin/python3 modules/param_miner.py -u https://target.com/page
../.venv/bin/python3 modules/param_miner.py -u https://target.com/api -f seclists-params --json
../.venv/bin/python3 modules/param_miner.py -u https://target.com/page -o params.json
```

### Secret Finder

```bash
../.venv/bin/python3 modules/secret_finder.py -u https://target.com
../.venv/bin/python3 modules/secret_finder.py -u https://target.com --crawl
../.venv/bin/python3 modules/secret_finder.py -f response.txt
```

### DNS Rebinding

```bash
../.venv/bin/python3 modules/dns_rebinding.py --attacker-domain rebind.attacker.com --target 127.0.0.1 --port 8080 -o attack.html
../.venv/bin/python3 modules/dns_rebinding.py --attacker-domain rebind.attacker.com --scan
```

---

## Injection & Active Scanning

### Active Scan

```bash
../.venv/bin/python3 modules/active_scan.py -u "https://target.com/page?id=1&name=test"
```

### sqlmap (via vendor/sqlmap @ HEAD)

```bash
../.venv/bin/python3 modules/sqlmap_scanner.py -u "https://target.com/page?id=1"
../.venv/bin/python3 modules/sqlmap_scanner.py -u https://target.com/login -d "user=admin&pass=x"
../.venv/bin/python3 modules/sqlmap_scanner.py -u "https://target.com/page?id=1" --get-dbs --get-tables
../.venv/bin/python3 modules/sqlmap_scanner.py -u "https://target.com/page?id=1" --dump --level 3 --risk 2
../.venv/bin/python3 modules/sqlmap_scanner.py -u "https://target.com/page?id=1" --dbms mysql --technique T
```

### commix (via vendor/commix @ HEAD)

```bash
../.venv/bin/python3 modules/commix_scanner.py -u "https://target.com/ping?host=127.0.0.1"
../.venv/bin/python3 modules/commix_scanner.py -u https://target.com/exec -d "cmd=test"
../.venv/bin/python3 modules/commix_scanner.py -u "https://target.com/page?id=1" --technique classic
# Techniques: classic, eval, time, file
```

### wapiti

```bash
../.venv/bin/python3 modules/wapiti_scanner.py -u https://target.com
../.venv/bin/python3 modules/wapiti_scanner.py -u https://target.com --depth 3 --module xss,sql
../.venv/bin/python3 modules/wapiti_scanner.py -u https://target.com --cookie "session=abc" -o report.json
```

### NoSQL Scanner

```bash
../.venv/bin/python3 modules/nosql_scanner.py -u https://target.com/login -d "user=admin&pass=x"
../.venv/bin/python3 modules/nosql_scanner.py -u https://target.com/api/login --json
../.venv/bin/python3 modules/nosql_scanner.py -u https://target.com/login --cookie "session=abc" -o findings.json
```

### LDAP Scanner

```bash
../.venv/bin/python3 modules/ldap_scanner.py -u https://target.com/login --user-field username --pass-field password
../.venv/bin/python3 modules/ldap_scanner.py -u https://target.com/search?q=test
../.venv/bin/python3 modules/ldap_scanner.py -u https://target.com/login -o findings.json
```

### SSRF Scanner

```bash
../.venv/bin/python3 modules/ssrf_scanner.py -u "https://target.com/fetch?url=test"
../.venv/bin/python3 modules/ssrf_scanner.py -u https://target.com/api -p url,src,dest
../.venv/bin/python3 modules/ssrf_scanner.py -u https://target.com/proxy -d '{"url":"FUZZ"}' --json
../.venv/bin/python3 modules/ssrf_scanner.py -u "https://target.com/fetch?url=test" --oob your.interact.sh
../.venv/bin/python3 modules/ssrf_scanner.py -u "https://target.com/fetch?url=test" --no-cloud --no-file
# Flags: --no-cloud  --no-internal  --no-file  --no-bypass  --protocol (adds dict:// gopher://)
```

### SSTI Scanner

```bash
../.venv/bin/python3 modules/ssti_scanner.py -u "https://target.com/render?name=test"
../.venv/bin/python3 modules/ssti_scanner.py -u https://target.com/greet -d "name=test" --post
../.venv/bin/python3 modules/ssti_scanner.py -u https://target.com/api -d '{"msg":"test"}' --json
../.venv/bin/python3 modules/ssti_scanner.py -u "https://target.com/page?q=x" -p q,template,msg
../.venv/bin/python3 modules/ssti_scanner.py -u https://target.com/render -d "name=x" --post -o findings.json
# Engines: Jinja2, Twig, Freemarker, Mako, Smarty, Velocity, ERB, OGNL, Nunjucks
```

### XXE Scanner

```bash
../.venv/bin/python3 modules/xxe_scanner.py -u https://target.com/api/parse -d '<root/>'
../.venv/bin/python3 modules/xxe_scanner.py -u https://target.com/api/parse --oob your.interact.sh
../.venv/bin/python3 modules/xxe_scanner.py -u https://target.com/upload --svg
../.venv/bin/python3 modules/xxe_scanner.py -u https://target.com/api -d '<user/>' -o findings.json
```

### CRLF Scanner

```bash
../.venv/bin/python3 modules/crlf_scanner.py -u "https://target.com/page?next=/home"
../.venv/bin/python3 modules/crlf_scanner.py -u https://target.com -p next,redirect,url,return
../.venv/bin/python3 modules/crlf_scanner.py -u "https://target.com/redir?url=x" -o findings.json
```

### Open Redirect

```bash
../.venv/bin/python3 modules/open_redirect.py -u "https://target.com/login?next=/dashboard"
../.venv/bin/python3 modules/open_redirect.py -u https://target.com -p next,redirect,url,return,goto
../.venv/bin/python3 modules/open_redirect.py -u "https://target.com/redir?url=x" --evil attacker.io
../.venv/bin/python3 modules/open_redirect.py -u "https://target.com/redir?url=x" -o findings.json
```

### Prototype Pollution

```bash
../.venv/bin/python3 modules/prototype_pollution.py -u https://target.com/api/settings -d '{"theme":"dark"}' --method POST
../.venv/bin/python3 modules/prototype_pollution.py -u "https://target.com/search?q=test"
../.venv/bin/python3 modules/prototype_pollution.py -u https://target.com/api --no-query
../.venv/bin/python3 modules/prototype_pollution.py -u https://target.com/api -d '{"x":1}' -o findings.json
```

### CORS Scanner

```bash
../.venv/bin/python3 modules/cors_scanner.py -u https://target.com/api/data
../.venv/bin/python3 modules/cors_scanner.py -u https://target.com/api --cookie "session=abc"
../.venv/bin/python3 modules/cors_scanner.py -u https://target.com/api -o findings.json
```

### HTTP Smuggler

```bash
../.venv/bin/python3 modules/smuggler.py -u https://target.com
../.venv/bin/python3 modules/smuggler.py -u https://target.com --timeout 15
```

### GraphQL Raider

```bash
../.venv/bin/python3 modules/graphql_raider.py -u https://target.com/graphql
../.venv/bin/python3 modules/graphql_raider.py -u https://target.com --discover
../.venv/bin/python3 modules/graphql_raider.py -u https://target.com/graphql --inject
../.venv/bin/python3 modules/graphql_raider.py -u https://target.com/graphql --batch 100
../.venv/bin/python3 modules/graphql_raider.py -u https://target.com/graphql -o report.json
```

### Upload Scanner

```bash
../.venv/bin/python3 modules/upload_scanner.py -u https://target.com/upload -f file
../.venv/bin/python3 modules/upload_scanner.py -u https://target.com/upload -f file --cookie "session=abc"
```

### 403 Bypass

```bash
../.venv/bin/python3 modules/bypass_403.py -u https://target.com -p /admin
../.venv/bin/python3 modules/bypass_403.py -u https://target.com -p /admin --cookie "session=abc"
```

---

## Authentication & Session

### JWT Analyser

```bash
../.venv/bin/python3 modules/jwt_analyser.py --decode <token>
../.venv/bin/python3 modules/jwt_analyser.py --algnone <token>
../.venv/bin/python3 modules/jwt_analyser.py --tamper <token> --claim '{"role":"admin"}'
../.venv/bin/python3 modules/jwt_analyser.py --crack <token> -w rockyou.txt
# Also tests: RS256→HS256 confusion, kid injection, expired token acceptance
```

### OAuth Tester

```bash
../.venv/bin/python3 modules/oauth_tester.py -u https://target.com --discover
../.venv/bin/python3 modules/oauth_tester.py --auth-url https://auth.target.com/authorize --client-id abc --redirect-uri https://target.com/cb
```

### CSRF PoC

```bash
../.venv/bin/python3 modules/csrf_poc.py -r request.txt -o poc.html
```

### User Enumeration

```bash
../.venv/bin/python3 modules/user_enum.py -u https://target.com/login
../.venv/bin/python3 modules/user_enum.py -u https://target.com/login --user-field email --pass-field password
../.venv/bin/python3 modules/user_enum.py -u https://target.com/login -w seclists-usernames
../.venv/bin/python3 modules/user_enum.py -u https://target.com/login --no-timing
../.venv/bin/python3 modules/user_enum.py -u https://target.com/login --cookie "session=abc" -o findings.json
```

### IDOR / BOLA Scanner

```bash
# Session swap: test if User B can read User A's resource
../.venv/bin/python3 modules/idor_scanner.py -u https://target.com/api/orders/1042 \
    --session-a "Authorization: Bearer TOKEN_A" \
    --session-b "Authorization: Bearer TOKEN_B"

# Enumerate adjacent numeric IDs
../.venv/bin/python3 modules/idor_scanner.py -u https://target.com/api/users/500 \
    --session-b "Cookie: session=SESS_B" --enumerate --range 10

# Test a file of endpoints
../.venv/bin/python3 modules/idor_scanner.py --url-file endpoints.txt \
    --session-a "Authorization: Bearer A" --session-b "Authorization: Bearer B" -o findings.json
```

### Autorize

```bash
../.venv/bin/python3 modules/autorize.py -u https://target.com --low-priv-cookie "session=low_priv_token"
```

### Cookie Analyser

```bash
../.venv/bin/python3 modules/cookie_analyser.py -u https://target.com
../.venv/bin/python3 modules/cookie_analyser.py -u https://target.com --login-url https://target.com/login --user admin --pass admin123
../.venv/bin/python3 modules/cookie_analyser.py -u https://target.com -o findings.json
```

### Sequencer

```bash
../.venv/bin/python3 modules/sequencer.py -f tokens.txt
../.venv/bin/python3 modules/sequencer.py -u https://target.com/token --samples 200
```

---

## Passive Analysis

### Security Headers

```bash
../.venv/bin/python3 modules/security_headers.py -u https://target.com
../.venv/bin/python3 modules/security_headers.py -u https://target.com -o findings.json
```

### TLS / SSL Scanner

```bash
../.venv/bin/python3 modules/ssl_tls_scanner.py -u https://target.com
../.venv/bin/python3 modules/ssl_tls_scanner.py --host target.com --port 443
../.venv/bin/python3 modules/ssl_tls_scanner.py -u https://target.com -o findings.json
# Checks: TLS 1.0/1.1, weak ciphers, cert expiry, self-signed, CN mismatch, HSTS
```

### Sensitive Data

```bash
../.venv/bin/python3 modules/sensitive_data.py -u https://target.com
../.venv/bin/python3 modules/sensitive_data.py -f response.html
```

### Insecure Transmission

```bash
../.venv/bin/python3 modules/insecure_transmission.py -u https://target.com
```

### RetireJS

```bash
../.venv/bin/python3 modules/retire_js.py -u https://target.com
```

---

## Workflow & Reporting

### Finding Tracker

```bash
../.venv/bin/python3 modules/finding_tracker.py --list
../.venv/bin/python3 modules/finding_tracker.py --list --severity critical,high
../.venv/bin/python3 modules/finding_tracker.py --list --status pending
../.venv/bin/python3 modules/finding_tracker.py --list --source cors_scanner
../.venv/bin/python3 modules/finding_tracker.py --stats
../.venv/bin/python3 modules/finding_tracker.py --get <id>
../.venv/bin/python3 modules/finding_tracker.py --confirm <id>
../.venv/bin/python3 modules/finding_tracker.py --confirm <id> --note "Verified on prod"
../.venv/bin/python3 modules/finding_tracker.py --reject <id> --note "Only on staging"
../.venv/bin/python3 modules/finding_tracker.py --wontfix <id>
../.venv/bin/python3 modules/finding_tracker.py --fixed <id>
../.venv/bin/python3 modules/finding_tracker.py --note <id> "CVSS 9.1 — fast patch needed"
../.venv/bin/python3 modules/finding_tracker.py --tag <id> waf-bypass
../.venv/bin/python3 modules/finding_tracker.py --delete <id>
../.venv/bin/python3 modules/finding_tracker.py --export report.json
../.venv/bin/python3 modules/finding_tracker.py --export report.json --status confirmed
../.venv/bin/python3 modules/finding_tracker.py --import findings.json
../.venv/bin/python3 modules/finding_tracker.py --clear
# DB: ~/.catch403/findings.db
```

### Report Generator

```bash
../.venv/bin/python3 modules/report_generator.py -o report.html
../.venv/bin/python3 modules/report_generator.py -o report.html --target "target.com" --tester "Alice" --scope "*.target.com"
../.venv/bin/python3 modules/report_generator.py -o report.html --status confirmed
../.venv/bin/python3 modules/report_generator.py --findings export.json -o report.html
# Output: self-contained HTML with inline CSS, severity chart, finding cards, curl commands
```

### AI Assist

```bash
../.venv/bin/python3 modules/ai_assist.py --set-key sk-ant-...

# Analyse a request/response pair
../.venv/bin/python3 modules/ai_assist.py --analyse --request req.txt --response resp.txt
../.venv/bin/python3 modules/ai_assist.py --analyse --request-text "GET /page HTTP/1.1..." --response-text "HTTP/1.1 200..."

# Explain or report on a finding
../.venv/bin/python3 modules/ai_assist.py --explain --finding-id 3
../.venv/bin/python3 modules/ai_assist.py --explain --finding findings.json
../.venv/bin/python3 modules/ai_assist.py --report --finding-id 3 -o section.md

# Generate payloads
../.venv/bin/python3 modules/ai_assist.py --suggest "SQLi in login form, MySQL backend, WAF present"

# Batch triage all pending findings
../.venv/bin/python3 modules/ai_assist.py --triage

# Free-form security question
../.venv/bin/python3 modules/ai_assist.py --ask "How do I exploit HTTP/2 request tunnelling on nginx?"
# Key stored at: ~/.catch403/config.json  (chmod 600)
```

### Vulnerability Chainer

```bash
../.venv/bin/python3 modules/vuln_chainer.py
../.venv/bin/python3 modules/vuln_chainer.py --pending       # include pending findings too
../.venv/bin/python3 modules/vuln_chainer.py --rules         # list all 12 chain detection rules
../.venv/bin/python3 modules/vuln_chainer.py --json confirmed.json
../.venv/bin/python3 modules/vuln_chainer.py --json confirmed.json -o chains.json
# Detects: CORS+CSRF, Open Redirect+OAuth, SSRF+Metadata, IDOR+Data,
#          XSS+CSRF, JWT+Privilege, SQLi+UserEnum, SubdomainTakeover+Cookie, and more
```

### CI/CD Runner

```bash
# First run — save baseline
../.venv/bin/python3 modules/cicd_runner.py -u https://staging.app.com --save-baseline

# Subsequent runs — new findings only
../.venv/bin/python3 modules/cicd_runner.py -u https://staging.app.com

# Custom profile and severity gate
../.venv/bin/python3 modules/cicd_runner.py -u https://staging.app.com --profile full --severity critical

# SARIF output (GitHub Code Scanning)
../.venv/bin/python3 modules/cicd_runner.py -u https://staging.app.com --sarif results.sarif

# All findings (no baseline diff)
../.venv/bin/python3 modules/cicd_runner.py -u https://staging.app.com --no-diff --output scan.json

# GitHub Actions PR comment
../.venv/bin/python3 modules/cicd_runner.py -u $TARGET_URL \
    --github-token $GITHUB_TOKEN --pr $PR_NUMBER --repo owner/repo

# Scan profiles: quick | standard | full | api
# Exit codes: 0 = no findings above threshold, 1 = findings above threshold
```

### OOB Helper (Collaborator alternative)

```bash
# Register a free interactsh session
../.venv/bin/python3 modules/oob_helper.py --start

# Check session status
../.venv/bin/python3 modules/oob_helper.py --status

# Generate a per-test canary token
../.venv/bin/python3 modules/oob_helper.py --generate --token ssrf-login-endpoint
# → URL:  http://a1b2c3d4.oast.pro/
# → DNS:  a1b2c3d4.oast.pro

# Poll for interactions
../.venv/bin/python3 modules/oob_helper.py --poll
../.venv/bin/python3 modules/oob_helper.py --poll --filter a1b2c3d4

# Quick canary (no registration, check DNS logs manually)
../.venv/bin/python3 modules/oob_helper.py --canary
../.venv/bin/python3 modules/oob_helper.py --canary --token blind-xss-comment

# Use a custom interactsh server
../.venv/bin/python3 modules/oob_helper.py --start --server https://your-interactsh.internal
```

---

## Fuzzing

### Intruder

```bash
../.venv/bin/python3 modules/intruder.py <request_file> -p payloads.txt -m sniper
../.venv/bin/python3 modules/intruder.py <request_file> -p p1.txt -p p2.txt -m clusterbomb
# Modes: sniper, batteringram, pitchfork, clusterbomb
# No rate throttle — unlike Burp Community Edition
```

### Turbo Intruder

```bash
../.venv/bin/python3 modules/turbo_intruder.py -u "https://target.com/search?q=%s" -w wordlist.txt -t 50
../.venv/bin/python3 modules/turbo_intruder.py -u https://target.com/login -d "user=admin&pass=%s" -w passwords.txt
../.venv/bin/python3 modules/turbo_intruder.py -u https://target.com/redeem -d "code=PROMO" --race 50
../.venv/bin/python3 modules/turbo_intruder.py -u https://target.com/search?q=%s -w w.txt --all -o out.json
```

---

## Utilities

### Wordlists

```bash
../.venv/bin/python3 modules/wordlists.py --list                  # all wordlists with line counts
../.venv/bin/python3 modules/wordlists.py --list paths            # by category
../.venv/bin/python3 modules/wordlists.py --categories            # list categories
../.venv/bin/python3 modules/wordlists.py --preview seclists-paths
# Categories: paths, params, usernames, passwords, subdomains, payloads, lfi, sqli, xss
```

### Hackvertor

```bash
../.venv/bin/python3 modules/hackvertor.py '<@url_encode>hello world<@/url_encode>'
../.venv/bin/python3 modules/hackvertor.py '<@b64_encode><@url_encode>test<@/url_encode><@/b64_encode>'
../.venv/bin/python3 modules/hackvertor.py --list
echo "hello" | ../.venv/bin/python3 modules/hackvertor.py --stdin --tag md5
```

### Hash ID

```bash
../.venv/bin/python3 modules/hash_id.py -H 5d41402abc4b2a76b9719d911017c592
../.venv/bin/python3 modules/hash_id.py -H <hash> -w rockyou.txt
../.venv/bin/python3 modules/hash_id.py -f hashes.txt --crack -w rockyou.txt
```

### Sequencer

```bash
../.venv/bin/python3 modules/sequencer.py -f tokens.txt
../.venv/bin/python3 modules/sequencer.py -u https://target.com/token --samples 200
```

### Response Beautifier

```bash
../.venv/bin/python3 modules/response_beautifier.py -f response.txt
../.venv/bin/python3 modules/response_beautifier.py --stdin < response.txt
```

### Collaborator (OOB payload generator)

```bash
../.venv/bin/python3 modules/collaborator.py --domain xyz.oast.me
../.venv/bin/python3 modules/collaborator.py --domain xyz.oast.me --all
../.venv/bin/python3 modules/collaborator.py --domain xyz.oast.me --type ssrf
../.venv/bin/python3 modules/collaborator.py --domain xyz.oast.me --type log4shell
# For full OOB session management with polling, use oob_helper.py instead
```

---

## Tests

```bash
../.venv/bin/python3 tests.py                # core tests
../.venv/bin/python3 tests_modules.py        # module tests
../.venv/bin/python3 tests_new_modules.py    # 170 tests — all new modules
```
