# Installation

## Requirements

- Python 3.11+
- A modern browser (Chrome, Firefox, Edge)

## Steps

```bash
git clone https://github.com/pshuker/catch403.git
cd catch403

python3 -m venv .venv
.venv/bin/pip install requests beautifulsoup4 lxml tabulate cryptography
```

## Start the web UI

```bash
cd proxyplatform
../.venv/bin/python3 web/server.py
# → http://localhost:8888
```

## HTTPS interception setup

Start the MITM proxy once to generate the CA certificate:

```bash
../.venv/bin/python3 modules/intercepting_proxy.py
```

Then import `~/.proxyplatform/ca/ca.crt` into your browser:

| Browser | Path |
|---|---|
| Chrome | Settings → Privacy → Security → Manage certificates → Authorities → Import |
| Firefox | Settings → Privacy → Certificates → View Certificates → Authorities → Import |
| Edge | Settings → Privacy → Manage certificates → Trusted Root → Import |

Set your browser proxy to `localhost:8080`.

## Custom port

```bash
../.venv/bin/python3 web/server.py --port 9999
../.venv/bin/python3 modules/intercepting_proxy.py --port 8081
```
