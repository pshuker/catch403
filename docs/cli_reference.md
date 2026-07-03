# CLI Reference

All commands run from the `proxyplatform/` directory using the venv Python.

## Web UI server

```bash
../.venv/bin/python3 web/server.py [--port 8888] [--host 127.0.0.1]
```

## Intercepting proxy

```bash
../.venv/bin/python3 modules/intercepting_proxy.py [--port 8080] [--host 127.0.0.1] [--scope target.com]
../.venv/bin/python3 modules/intercepting_proxy.py --ca-info
```

## Traffic logger

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

## Scope

```bash
../.venv/bin/python3 modules/scope.py add target.com
../.venv/bin/python3 modules/scope.py add staging.target.com --exclude
../.venv/bin/python3 modules/scope.py list
../.venv/bin/python3 modules/scope.py remove 0
../.venv/bin/python3 modules/scope.py check https://target.com/login
../.venv/bin/python3 modules/scope.py clear
```

## Intruder

```bash
../.venv/bin/python3 modules/intruder.py <request_file> -p payloads.txt -m sniper
../.venv/bin/python3 modules/intruder.py <request_file> -p p1.txt -p p2.txt -m clusterbomb
# Modes: sniper, batteringram, pitchfork, clusterbomb
```

## Turbo Intruder

```bash
../.venv/bin/python3 modules/turbo_intruder.py -u https://target.com/search?q=%s -w wordlist.txt -t 50
../.venv/bin/python3 modules/turbo_intruder.py -u https://target.com/login -d 'user=admin&pass=%s' -w passwords.txt
../.venv/bin/python3 modules/turbo_intruder.py -u https://target.com/redeem -d 'code=PROMO' --race 50
../.venv/bin/python3 modules/turbo_intruder.py ... --all      # show all results, not just interesting
../.venv/bin/python3 modules/turbo_intruder.py ... -o out.json
```

## Content Discovery

```bash
../.venv/bin/python3 modules/content_discovery.py -u https://target.com
../.venv/bin/python3 modules/content_discovery.py -u https://target.com -w wordlist.txt -e php,txt,bak -t 40 -r
../.venv/bin/python3 modules/content_discovery.py -u https://target.com --status 200,301,403 -o results.json
```

## Active Scan

```bash
../.venv/bin/python3 modules/active_scan.py -u "https://target.com/page?id=1&name=test"
```

## 403 Bypass

```bash
../.venv/bin/python3 modules/bypass_403.py -u https://target.com -p /admin
../.venv/bin/python3 modules/bypass_403.py -u https://target.com -p /admin --cookie "session=abc"
```

## HTTP Smuggler

```bash
../.venv/bin/python3 modules/smuggler.py -u https://target.com
../.venv/bin/python3 modules/smuggler.py -u https://target.com --timeout 15
```

## JWT Analyser

```bash
../.venv/bin/python3 modules/jwt_analyser.py --decode <token>
../.venv/bin/python3 modules/jwt_analyser.py --algnone <token>
../.venv/bin/python3 modules/jwt_analyser.py --tamper <token> --claim '{"role":"admin"}'
../.venv/bin/python3 modules/jwt_analyser.py --crack <token> -w rockyou.txt
```

## OAuth Tester

```bash
../.venv/bin/python3 modules/oauth_tester.py -u https://target.com --discover
../.venv/bin/python3 modules/oauth_tester.py --auth-url https://auth.target.com/authorize --client-id abc --redirect-uri https://target.com/cb
```

## GraphQL Raider

```bash
../.venv/bin/python3 modules/graphql_raider.py -u https://target.com/graphql
../.venv/bin/python3 modules/graphql_raider.py -u https://target.com --discover
../.venv/bin/python3 modules/graphql_raider.py -u https://target.com/graphql --inject
../.venv/bin/python3 modules/graphql_raider.py -u https://target.com/graphql --batch 100
../.venv/bin/python3 modules/graphql_raider.py -u https://target.com/graphql -o report.json
```

## Secret Finder

```bash
../.venv/bin/python3 modules/secret_finder.py -u https://target.com
../.venv/bin/python3 modules/secret_finder.py -f file.txt
../.venv/bin/python3 modules/secret_finder.py -u https://target.com --crawl
```

## RetireJS

```bash
../.venv/bin/python3 modules/retire_js.py -u https://target.com
```

## Upload Scanner

```bash
../.venv/bin/python3 modules/upload_scanner.py -u https://target.com/upload -f file
../.venv/bin/python3 modules/upload_scanner.py -u https://target.com/upload -f file --cookie "session=abc"
```

## Spider

```bash
../.venv/bin/python3 modules/spider.py -u https://target.com
../.venv/bin/python3 modules/spider.py -u https://target.com --depth 5 --delay 0.5
```

## Collaborator (OOB payloads)

```bash
../.venv/bin/python3 modules/collaborator.py --domain xyz.oast.me
../.venv/bin/python3 modules/collaborator.py --domain xyz.oast.me --all
../.venv/bin/python3 modules/collaborator.py --domain xyz.oast.me --type ssrf
../.venv/bin/python3 modules/collaborator.py --domain xyz.oast.me --type log4shell
```

## DNS Rebinding

```bash
../.venv/bin/python3 modules/dns_rebinding.py --attacker-domain rebind.attacker.com --target 127.0.0.1 --port 8080 -o attack.html
../.venv/bin/python3 modules/dns_rebinding.py --attacker-domain rebind.attacker.com --scan
```

## Hackvertor

```bash
../.venv/bin/python3 modules/hackvertor.py '<@url_encode>hello world<@/url_encode>'
../.venv/bin/python3 modules/hackvertor.py '<@b64_encode><@url_encode>test<@/url_encode><@/b64_encode>'
../.venv/bin/python3 modules/hackvertor.py --list
echo "hello" | ../.venv/bin/python3 modules/hackvertor.py --stdin --tag md5
```

## Hash ID

```bash
../.venv/bin/python3 modules/hash_id.py -H 5d41402abc4b2a76b9719d911017c592
../.venv/bin/python3 modules/hash_id.py -H <hash> -w rockyou.txt
../.venv/bin/python3 modules/hash_id.py -f hashes.txt --crack -w rockyou.txt
```

## Sequencer

```bash
../.venv/bin/python3 modules/sequencer.py -f tokens.txt
../.venv/bin/python3 modules/sequencer.py -u https://target.com/token --samples 200
```

## Comparer

```bash
../.venv/bin/python3 modules/comparer.py a.txt b.txt
../.venv/bin/python3 modules/comparer.py a.txt b.txt --similarity
```

## CSRF PoC

```bash
../.venv/bin/python3 modules/csrf_poc.py -r request.txt -o poc.html
```

## Param Miner

```bash
../.venv/bin/python3 modules/param_miner.py -u https://target.com/page
../.venv/bin/python3 modules/param_miner.py -u https://target.com/api -w wordlist.txt --json
```

## Auto Repeater

```bash
../.venv/bin/python3 modules/auto_repeater.py --demo
../.venv/bin/python3 modules/auto_repeater.py --export rules.json
../.venv/bin/python3 modules/auto_repeater.py --rules my_rules.json
```

## Tests

```bash
../.venv/bin/python3 tests.py
../.venv/bin/python3 tests_modules.py
../.venv/bin/python3 tests_new_modules.py
```
