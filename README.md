# Catch403

A Burp Suite-style web security testing platform built in Python. Intercept, inspect, and attack HTTP/HTTPS traffic through a dark-themed browser UI — no Java, no licence fees.

![Python](https://img.shields.io/badge/python-3.11+-blue) ![Tests](https://img.shields.io/badge/tests-146%20passing-4ec9a5) ![Modules](https://img.shields.io/badge/modules-30-4c8dff) ![License](https://img.shields.io/badge/license-MIT-9d7cff)

---

## Features

| Category | Modules |
|---|---|
| **Proxy** | Intercepting MITM proxy (HTTP + HTTPS), Logger+, Auto Repeater, Scope Manager |
| **Active testing** | Active Scan++, HTTP Smuggler, 403 Bypass, Upload Scanner, Content Discovery |
| **Passive analysis** | Secret Finder, RetireJS, Security Headers, Sensitive Data, Insecure Transmission |
| **Auth testing** | JWT Analyser, OAuth/OIDC Tester, Autorize |
| **Injection** | Intruder, Turbo Intruder, Param Miner, GraphQL Raider, CSRF PoC |
| **Recon** | Spider, DNS Rebinding, Collaborator (OOB payloads) |
| **Utilities** | Hackvertor, Comparer, Sequencer, Hash ID, Response Beautifier, Decoder |

**Web UI** — dark obsidian/blue theme with light mode toggle, tabbed layout, split panes. Runs in your browser at `localhost:8888`.

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/pshuker/catch403.git
cd catch403

# 2. Create venv and install deps
python3 -m venv .venv
.venv/bin/pip install requests beautifulsoup4 lxml tabulate cryptography

# 3. Start the web UI
cd proxyplatform
../.venv/bin/python3 web/server.py

# 4. Open browser
# http://localhost:8888
```

### HTTPS interception (optional)

```bash
# Start the MITM proxy
../.venv/bin/python3 modules/intercepting_proxy.py

# Import the generated CA cert into your browser
# ~/.proxyplatform/ca/ca.crt

# Set browser proxy: localhost:8080
```

---

## Project layout

```
catch403/
├── proxyplatform/
│   ├── core/               # Flow model, module system, tools, ZAP bridge
│   ├── modules/            # 30 security testing modules
│   ├── Burpee/             # Burp request file parser
│   ├── web/
│   │   ├── server.py       # HTTP API server (port 8888)
│   │   └── index.html      # Single-file web UI
│   ├── tests.py            # Core test suite (32 tests)
│   ├── tests_modules.py    # Module test suite (59 tests)
│   └── tests_new_modules.py # Extended test suite (55 tests)
└── docs/                   # Full documentation
```

---

## Running tests

```bash
cd proxyplatform
../.venv/bin/python3 tests.py              # 32 core tests
../.venv/bin/python3 tests_modules.py      # 59 module tests
../.venv/bin/python3 tests_new_modules.py  # 55 extended tests
```

---

## Docs

- [Installation](docs/installation.md)
- [Web UI](docs/web_ui.md)
- [Intercepting Proxy](docs/intercepting_proxy.md)
- [Modules](docs/modules.md)
- [Writing a Module](docs/writing_modules.md)
- [CLI Reference](docs/cli_reference.md)

---

## Legal

Use only against systems you own or have explicit written authorisation to test. Unauthorised use against third-party systems is illegal in most jurisdictions.
