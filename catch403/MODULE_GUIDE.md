# Writing a Module — Developer Guide

The platform is a foundation: the proxy pipeline, the Flow model, the manual
tools, and this plugin system. You extend it by writing **modules** against the
documented API below. Modules can inspect, annotate, mutate, or drop the HTTP
flows moving through the pipeline.

---

## The basics

A module is a Python class that subclasses `BaseModule`, sets a `name`, and
implements whichever hooks it needs. Drop the file in `modules/` (or load it
explicitly) and it hooks into the pipeline.

```python
from core.modules import BaseModule
from core.flow import Flow

class MyModule(BaseModule):
    name = "my-module"

    def on_request(self, flow: Flow) -> None:
        ...   # called for every request before it's sent

    def on_response(self, flow: Flow) -> None:
        ...   # called for every response before it's returned
```

---

## The four hooks (all optional)

| Hook | When it runs | Typical use |
|------|--------------|-------------|
| `on_request(self, flow)`  | before a request is sent     | inspect/annotate/mutate the request |
| `on_response(self, flow)` | before a response is returned | inspect/annotate the response |
| `on_load(self)`           | once, when the module registers | setup |
| `on_unload(self)`         | once, when the module is removed | teardown |

Implement only what you need — the base class provides no-op defaults for the rest.

---

## What you can do with a `flow`

The `Flow` object (see `core/flow.py` — it's short and readable) is one HTTP
exchange. It gives you:

**Read the request**
```python
flow.request.method        # "GET", "POST", ...
flow.request.url           # full URL
flow.request.host          # netloc
flow.request.path          # path
flow.request.query         # {name: [values]}
flow.request.header("X")   # case-insensitive header lookup
flow.request.body          # bytes
```

**Read the response** (may be `None` during `on_request`)
```python
flow.response.status       # int
flow.response.header("X")  # case-insensitive lookup
flow.response.body         # bytes
```

**Annotate**
```python
flow.tag("label")          # add a tag (used for filtering in History)
flow.note("free text")     # attach a note
```

**Report a structured finding** (the results API)
```python
flow.add_finding(self.name, "Short title",
                 severity="high",     # info | low | medium | high
                 detail="longer explanation")
```
Findings are aggregated across traffic by `History.findings()` and
`History.findings_summary()` — the platform's results view.

**Mutate**
```python
flow.request.set_header("User-Agent", "custom")
flow.request.set_query({"id": "5"})
# or edit flow.request.headers / flow.request.body directly
```

**Drop** (stop the flow being forwarded)
```python
flow.drop()
```

**Scratch space** (stash data for yourself or later hooks/modules)
```python
flow.meta["key"] = value
```

---

## A complete worked example

```python
from core.modules import BaseModule
from core.flow import Flow
import time

class SlowResponseFlagger(BaseModule):
    name = "slow-response-flagger"

    def on_request(self, flow: Flow) -> None:
        flow.meta["sent_at"] = time.time()

    def on_response(self, flow: Flow) -> None:
        elapsed = time.time() - flow.meta.get("sent_at", time.time())
        if elapsed > 2.0:
            flow.add_finding(self.name, "Slow response",
                             severity="low", detail=f"{elapsed:.1f}s")
```

---

## Loading modules

```python
from core.modules import ModuleManager

mgr = ModuleManager()
mgr.add(MyModule())                    # register an instance directly
mgr.load_file("path/to/my_module.py")  # load a .py file (finds BaseModule subclasses)
mgr.load_dir("modules/")               # load every module in a directory
mgr.list_modules()                     # names of loaded modules
```

The manager runs modules in registration order and **isolates them** — a module
that raises won't crash the pipeline; the error is captured to `flow.note(...)`
and `mgr.errors`.

---

## Good practice

- **Keep hooks fast** — they run on every flow.
- **Fail safe** — don't assume `flow.response` exists in `on_request`.
- **Use `add_finding` for results**, `note`/`tag` for lightweight annotation.
- **One responsibility per module** — easier to test and reuse.
- **Test it** — instantiate the module, hand it a `Flow`, assert on
  `flow.findings`. See `tests.py` for the pattern.

---

## Example modules to copy from

The platform ships with neutral, inspection-oriented modules that double as API
documentation:

| Module | Shows |
|--------|-------|
| `modules/security_headers.py`      | passive response inspection + annotation |
| `modules/insecure_transmission.py` | request inspection + high-severity finding |
| `modules/sensitive_data.py`        | response body pattern-matching + findings |

Copy whichever is closest to what you're building.

---

## Scope note

This framework provides the extension points and the plumbing. The bundled
example modules are passive and inspection-only. Any active-testing modules are
authored and added by the operator, who is responsible for using them only
against systems they are authorised to test. For active scanning through a
sanctioned engine (with its own scope/authorisation controls), see the OWASP ZAP
bridge in `core/zap_bridge.py`.
