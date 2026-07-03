# Proxy Platform — a modular web security testing foundation

An extensible intercepting-proxy platform with a clean loadable-module system.
This is the **foundation**: the proxy pipeline, manual-testing tools, and the
plugin architecture. You add the testing modules — write your own or wire in
ones from elsewhere — against the documented module API.

Stdlib-only, tested (18 tests), no third-party dependencies in the core.

## What's here

| Piece | File | What it does |
|-------|------|-------------|
| Flow model | `core/flow.py` | The Request/Response/Flow objects modules operate on |
| Module system | `core/modules.py` | Plugin interface + manager (load, run, isolate) |
| Manual tools | `core/tools.py` | Repeater (resend/modify) + Decoder (URL/base64/hex/HTML) |
| Pipeline state | `core/intercept.py` | Intercept hold-queue + traffic history with filtering |
| Example modules | `modules/security_headers.py`, `modules/insecure_transmission.py`, `modules/sensitive_data.py` | Passive inspectors (headers, plaintext-secrets, data-exposure) — templates to copy |
| Findings API | `core/flow.py` (`Finding`, `flow.add_finding`) | Structured results (severity + type), aggregated in `History.findings()` |
| Compatibility layer | `core/compat.py` | ZAP-style + Burp-style object shims — run scripts from those ecosystems here |
| ZAP bridge | `core/zap_bridge.py` | Drive ZAP's scanner via its API; ingest findings into the Flow model |

## Active scanning via ZAP (the engine)

Rather than reimplement a scanner, the platform **orchestrates OWASP ZAP's**
mature open-source engine and pulls results back into one view. Your platform is
the hub; ZAP is the scanning engine; findings live alongside proxied traffic.

```python
from core.zap_bridge import ZapClient, ZapScanner, findings_to_flows
from core.intercept import History

client = ZapClient(host="127.0.0.1", port=8080, api_key="YOUR_ZAP_API_KEY")
scanner = ZapScanner(client)

result = scanner.scan("http://your-authorised-target")   # spider -> active scan
print(result.summary())                                   # findings by risk

# fold findings into your History alongside proxied traffic
history = History()
for flow in findings_to_flows(result):
    history.add(flow)
history.filter(tag="risk:high")                            # triage
```

ZAP alerts are normalised into `Finding` objects (name, risk, confidence, URL,
param, evidence, CWE, solution) and can be represented as flows so scan results
and proxy history share one model.

**Requires ZAP running as a daemon** (it's a Java app — install and start it
separately, e.g. `zap.sh -daemon -config api.key=...`). This bridge talks to its
REST API; it does not bundle or reimplement the scanner. Active scanning sends
real traffic — **authorised targets only**.

## Porting ZAP / Burp scripts

The compatibility layer (`core/compat.py`) presents ZAP's and Burp's
request/response object APIs on top of our Flow, so a Python script written for
those tools runs here with little or no change.

```python
from core.compat import ZapScriptModule, BurpScriptModule
from core.modules import ModuleManager

# A ZAP passive script — its own scan(ps, msg, src) signature, unchanged:
def scan(ps, msg, src):
    if "error" in msg.getResponseBody().lower():
        ps.raiseAlert(risk=1, confidence=2, name="Error in response")

mgr = ModuleManager()
mgr.add(ZapScriptModule(scan, name="ported-zap-check"))   # runs in the pipeline
```

ZAP alerts become flow tags + notes; Burp comments/highlights map to notes/tags.
Supported accessors include ZAP's `getRequestHeader/Body`, `getResponseHeader/
Body`, `getHeader`, `raiseAlert`, and Burp's `getRequest/getResponse/getUrl/
getHttpService`, `setComment/setHighlight`.

**Limitation (by construction, not choice):** this runs *Python* scripts written
against the ZAP/Burp scripting APIs. It **cannot** load compiled Java extensions
(`.jar` Burp extensions or `.zap` add-ons) — those require the Burp/ZAP Java
runtime, which can't run inside a Python program. For those, run them in their
native tool.

## Writing a module

Subclass `BaseModule`, set a name, implement the hooks you need:

```python
from core.modules import BaseModule
from core.flow import Flow

class MyModule(BaseModule):
    name = "my-module"

    def on_request(self, flow: Flow) -> None:
        # inspect / annotate / mutate / drop the request
        flow.request.set_header("X-My-Header", "value")
        flow.note("my-module saw this request")

    def on_response(self, flow: Flow) -> None:
        if flow.response and flow.response.status == 500:
            flow.tag("server-error")
```

Hooks (all optional): `on_request(flow)`, `on_response(flow)`, `on_load()`,
`on_unload()`. In a hook you can:
- **inspect** — read `flow.request` / `flow.response`
- **annotate** — `flow.tag("label")`, `flow.note("text")`
- **mutate** — edit headers, body, URL, query
- **drop** — `flow.drop()` to block the flow
- **stash** — `flow.meta["key"] = ...` for other modules

A module that raises is caught and logged (`manager.errors`) — a broken module
can't crash the pipeline.

## Loading modules

```python
from core.modules import ModuleManager
mgr = ModuleManager()

mgr.add(MyModule())                    # register an instance
mgr.load_file("path/to/module.py")     # load a module file (e.g. one you pulled in)
mgr.load_dir("modules/")               # load every module in a directory
```

## Manual testing

```python
from core.tools import Repeater, Decoder
from core.flow import Request

rep = Repeater(transport)              # transport: Request -> Response
flow = rep.send(Request("GET", "https://target/"))   # authorised targets only

Decoder.apply("base64-encode", "data")
```

## Scope & responsible use

This foundation provides the **proxy pipeline and extension points**. It ships
with neutral, inspection-oriented example modules only. Any active-testing
modules are authored or added by you.

**Use only against systems you own or are explicitly authorised to test.** An
intercepting proxy and the modules you attach to it are powerful; pointing them
at systems you don't have permission to test is illegal in most jurisdictions
regardless of intent. Treat modules you pull from third parties like any
untrusted code — review before you run them, and run them isolated.

## Tests

```bash
python3 tests.py
```
