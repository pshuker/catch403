# Writing a Module

Every module in `proxyplatform/modules/` follows the same pattern — importable as a library and runnable as a CLI tool.

## Minimal module

```python
#!/usr/bin/python3
"""
My Module — one-line description.

Usage:
  ../.venv/bin/python3 modules/my_module.py -u https://target.com
"""
import argparse
import requests
import urllib3
from core.colors import bold, end, good, bad, info, run

urllib3.disable_warnings()

def scan(url: str) -> list[dict]:
    findings = []
    r = requests.get(url, timeout=10, verify=False)
    if "something_bad" in r.text:
        findings.append({
            "name":     "Bad thing found",
            "severity": "high",
            "detail":   f"Found at {url}",
        })
    return findings

def main():
    parser = argparse.ArgumentParser(description="My module")
    parser.add_argument("-u", dest="url", required=True)
    args = parser.parse_args()
    results = scan(args.url)
    for r in results:
        print(f"{bad} [{r['severity'].upper()}] {r['name']}: {r['detail']}")

if __name__ == "__main__":
    main()
```

## Conventions

| Convention | Rule |
|---|---|
| Entry point | `main()` function — never module-level `parse_args()` |
| Core function | Returns `list[dict]` with at least `name`, `severity`, `detail` |
| Colours | Import from `core.colors` — `good`, `bad`, `info`, `run`, `bold`, `end` |
| HTTP | Use `requests` from `.venv`, `verify=False`, `urllib3.disable_warnings()` |
| Argparse | Always inside `main()`, never at module level |
| Imports | Keep third-party imports at the top, core imports below |

## Severity levels

Use these strings consistently so the web UI can colour-code findings:

- `critical` — RCE, full auth bypass, data exfiltration
- `high` — SQLi, XSS, SSRF, broken auth
- `medium` — CSRF, open redirect, weak config
- `low` — Info disclosure, missing headers
- `info` — Informational, no direct impact

## Adding to the web UI

1. Add a `POST /api/your_module` route in `web/server.py`
2. Add a tab in `web/index.html`
3. Wire up the API call in the tab's JS

## Testing

Add tests to `tests_modules.py` or `tests_new_modules.py`. Import your module, test the core function directly — no HTTP calls in unit tests.

```python
from modules.my_module import scan

test("my_module finds bad thing", lambda: (
    assert_true(len(scan_some_fixture()) > 0)))
```
