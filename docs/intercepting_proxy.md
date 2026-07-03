# Intercepting Proxy

Catch403's MITM proxy intercepts HTTP and HTTPS traffic between your browser and the target. Configure your browser to use it as a proxy, then all traffic flows through — logged, inspectable, and replayable.

## Start

```bash
cd proxyplatform
../.venv/bin/python3 modules/intercepting_proxy.py
```

Default: `127.0.0.1:8080`

## Options

```
--host   Bind address (default: 127.0.0.1)
--port   Proxy port   (default: 8080)
--scope  Only log traffic to this host (e.g. target.com)
```

## HTTPS

On first run the proxy generates a CA certificate at `~/.proxyplatform/ca/ca.crt`. Import this into your browser's certificate store once — after that all HTTPS traffic is decrypted, inspected, and re-encrypted transparently.

Per-domain certificates are generated on demand and cached at `~/.proxyplatform/ca/certs/`.

## Traffic log

All intercepted traffic is saved to `~/.proxyplatform/traffic.db` (SQLite) and can be queried via Logger+:

```bash
../.venv/bin/python3 modules/logger_plus.py --list
../.venv/bin/python3 modules/logger_plus.py --list --host target.com --status 200
../.venv/bin/python3 modules/logger_plus.py --export traffic.json
../.venv/bin/python3 modules/logger_plus.py --get 42
```

## Scope

Limit logging to a specific host to reduce noise:

```bash
../.venv/bin/python3 modules/intercepting_proxy.py --scope target.com
```

Or manage scope rules persistently:

```bash
../.venv/bin/python3 modules/scope.py add target.com
../.venv/bin/python3 modules/scope.py add staging.target.com --exclude
../.venv/bin/python3 modules/scope.py list
```

## Auto Repeater integration

The proxy feeds intercepted requests into Auto Repeater rules automatically. Rules can strip auth headers, downgrade permissions, or inject headers — the modified response is diffed against the original and flagged if different.
