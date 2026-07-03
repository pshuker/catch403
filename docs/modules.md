# Modules Reference

All modules live in `proxyplatform/modules/`. Each can be imported as a library or run standalone from the CLI.

---

## Proxy & Traffic

### intercepting_proxy.py
MITM proxy with dynamic SSL cert generation per domain.
```bash
../.venv/bin/python3 modules/intercepting_proxy.py --port 8080 --scope target.com
```

### logger_plus.py
SQLite traffic log with filtering and export.
```bash
../.venv/bin/python3 modules/logger_plus.py --list --host target.com
../.venv/bin/python3 modules/logger_plus.py --export out.json
../.venv/bin/python3 modules/logger_plus.py --get 42
```

### scope.py
Define in-scope targets. All other modules respect these rules.
```bash
../.venv/bin/python3 modules/scope.py add target.com
../.venv/bin/python3 modules/scope.py add staging.target.com --exclude
../.venv/bin/python3 modules/scope.py list
../.venv/bin/python3 modules/scope.py check https://target.com/login
```

### auto_repeater.py
Rule-based automatic request resender with response diffing.
```bash
../.venv/bin/python3 modules/auto_repeater.py --demo
../.venv/bin/python3 modules/auto_repeater.py --export rules.json
```

---

## Fuzzing & Injection

### intruder.py
Burp Intruder-style fuzzer — Sniper, Battering Ram, Pitchfork, Cluster Bomb.
```bash
../.venv/bin/python3 modules/intruder.py request.txt -p payloads.txt -m sniper
../.venv/bin/python3 modules/intruder.py request.txt -p p1.txt -p p2.txt -m clusterbomb
```

### turbo_intruder.py
High-concurrency async fuzzer. Gate mechanism for race condition attacks.
```bash
# Wordlist attack
../.venv/bin/python3 modules/turbo_intruder.py -u https://target.com/search?q=%s -w wordlist.txt -t 50

# Race condition (50 simultaneous requests)
../.venv/bin/python3 modules/turbo_intruder.py -u https://target.com/redeem -d 'code=PROMO' --race 50
```

### param_miner.py
Discover hidden HTTP parameters.
```bash
../.venv/bin/python3 modules/param_miner.py -u https://target.com/page
../.venv/bin/python3 modules/param_miner.py -u https://target.com/api -w custom-params.txt
```

### content_discovery.py
Directory and file brute-forcer with extension fuzzing and recursive mode.
```bash
../.venv/bin/python3 modules/content_discovery.py -u https://target.com
../.venv/bin/python3 modules/content_discovery.py -u https://target.com -w /usr/share/wordlists/dirb/common.txt -e php,bak -r
```

---

## Active Testing

### active_scan.py
XSS, SQLi, SSTI, path traversal, open redirect, SSRF, command injection, CORS, security headers.
```bash
../.venv/bin/python3 modules/active_scan.py -u "https://target.com/page?id=1"
```

### bypass_403.py
25+ techniques to bypass 403 Forbidden responses.
```bash
../.venv/bin/python3 modules/bypass_403.py -u https://target.com -p /admin
```

### smuggler.py
HTTP Request Smuggling via raw sockets — CL.TE, TE.CL, TE.TE obfuscation variants.
```bash
../.venv/bin/python3 modules/smuggler.py -u https://target.com
```

### upload_scanner.py
File upload bypass — double extension, polyglots, MIME spoofing, null byte, path traversal.
```bash
../.venv/bin/python3 modules/upload_scanner.py -u https://target.com/upload -f file
```

### graphql_raider.py
GraphQL introspection, field injection, batch DoS, alias amplification.
```bash
../.venv/bin/python3 modules/graphql_raider.py -u https://target.com/graphql
../.venv/bin/python3 modules/graphql_raider.py -u https://target.com/graphql --introspect
../.venv/bin/python3 modules/graphql_raider.py -u https://target.com --discover
```

---

## Auth & Session

### jwt_analyser.py
JWT decode, alg:none, RS256→HS256 confusion, HMAC wordlist crack.
```bash
../.venv/bin/python3 modules/jwt_analyser.py --decode <token>
../.venv/bin/python3 modules/jwt_analyser.py --algnone <token>
../.venv/bin/python3 modules/jwt_analyser.py --crack <token> -w rockyou.txt
```

### oauth_tester.py
State param, redirect_uri bypass, PKCE enforcement, implicit flow, scope escalation, OIDC discovery.
```bash
../.venv/bin/python3 modules/oauth_tester.py -u https://target.com --discover
../.venv/bin/python3 modules/oauth_tester.py --auth-url https://auth.target.com/authorize --client-id abc --redirect-uri https://target.com/cb
```

### autorize.py
Broken access control — replay requests with low-priv or no auth.
```bash
../.venv/bin/python3 modules/autorize.py -r request.txt --cookie "session=lowpriv_token"
```

### csrf_poc.py
Generate an auto-submit HTML CSRF PoC from a raw Burp request file.
```bash
../.venv/bin/python3 modules/csrf_poc.py -r request.txt -o poc.html
```

---

## Passive Analysis

### secret_finder.py
40+ regex patterns — AWS keys, GitHub tokens, JWT, RSA keys, DB strings, Stripe, Twilio, etc.
```bash
../.venv/bin/python3 modules/secret_finder.py -u https://target.com
../.venv/bin/python3 modules/secret_finder.py -f response_body.txt
```

### retire_js.py
Detect vulnerable JavaScript libraries (jQuery, Bootstrap, Lodash, Angular, etc.).
```bash
../.venv/bin/python3 modules/retire_js.py -u https://target.com
```

### security_headers.py
Check for missing security headers — HSTS, CSP, X-Frame-Options, etc.

### sensitive_data.py
Detect PII, tokens, and secrets in response bodies.

### insecure_transmission.py
Flag mixed content and insecure resource loading.

---

## Recon & OOB

### spider.py
BFS web crawler — finds pages, links, forms, files, external URLs.
```bash
../.venv/bin/python3 modules/spider.py -u https://target.com --depth 3
```

### collaborator.py
OOB payload generator for blind SSRF, XSS, XXE, SQLi, SSTI, Log4Shell.
```bash
../.venv/bin/python3 modules/collaborator.py --domain xyz.oast.me --all
../.venv/bin/python3 modules/collaborator.py --domain xyz.oast.me --type ssrf
```

### dns_rebinding.py
DNS rebinding attack page generator and multi-port internal service scanner.
```bash
../.venv/bin/python3 modules/dns_rebinding.py --attacker-domain rebind.attacker.com --target 127.0.0.1 --port 8080 -o attack.html
../.venv/bin/python3 modules/dns_rebinding.py --attacker-domain x.com --scan
```

---

## Utilities

### hackvertor.py
Chainable tag-based encoding — `<@url_encode><@b64_encode>hello<@/b64_encode><@/url_encode>`.
```bash
../.venv/bin/python3 modules/hackvertor.py '<@url_encode>hello world<@/url_encode>'
../.venv/bin/python3 modules/hackvertor.py --list
```

### comparer.py
Unified diff between two files or text blocks.
```bash
../.venv/bin/python3 modules/comparer.py a.txt b.txt
```

### sequencer.py
Token entropy analysis — Shannon entropy, bit-level, monobit NIST test.
```bash
../.venv/bin/python3 modules/sequencer.py -f tokens.txt
```

### hash_id.py
Identify 30+ hash types and crack with a wordlist.
```bash
../.venv/bin/python3 modules/hash_id.py -H 5d41402abc4b2a76b9719d911017c592
../.venv/bin/python3 modules/hash_id.py -H <hash> -w rockyou.txt
../.venv/bin/python3 modules/hash_id.py -f hashes.txt --crack -w rockyou.txt
```

### response_beautifier.py
Pretty-print JSON, HTML, XML responses with syntax highlighting.
```bash
../.venv/bin/python3 modules/response_beautifier.py response.json
echo '{"a":1}' | ../.venv/bin/python3 modules/response_beautifier.py --ct application/json
```
