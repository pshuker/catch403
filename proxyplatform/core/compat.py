"""
Compatibility layer — run ZAP-style and Burp-style scripts on this platform.

This is neutral adapter plumbing. ZAP and Burp scripts call against *their*
request/response object APIs; this module presents those same interfaces on top
of our Flow object, so a script written for ZAP or Burp can run here with little
or no change. It translates method calls — it contains no testing logic of its
own; what a script does is the script's business and the operator's
responsibility.

Two shims:
  * ZapMessage      — mimics ZAP's HttpMessage (getRequestHeader/Body,
                      getResponseHeader/Body, setRequestBody, ...). ZAP passive
                      scripts are typically `def scan(ps, msg, src)`.
  * BurpRequestResponse — mimics Burp's IHttpRequestResponse-ish accessors
                      (getRequest/getResponse/getUrl/getHttpService).

Plus runners that call a loaded script's conventional entry point with the
shimmed objects, so you can drive ported scripts through the module pipeline.

IMPORTANT: this cannot load compiled Java extensions (.jar Burp extensions or
.zap add-ons) — those need the Burp/ZAP Java runtime and can't run in a Python
program. This targets *Python* scripts written against the ZAP/Burp scripting
APIs. Compiled/Java extensions are out of reach by construction, not by choice.
"""

from __future__ import annotations

from typing import Callable

from core.flow import Flow, Request, Response
from core.modules import BaseModule


# ---------------------------------------------------------------------------
# ZAP-style shim
# ---------------------------------------------------------------------------

class _ZapHeader:
    """Mimics ZAP's request/response header object (stringifiable, primitive)."""
    def __init__(self, start_line: str, headers: dict[str, str]):
        self._start = start_line
        self._headers = headers

    def __str__(self) -> str:
        lines = [self._start]
        lines += [f"{k}: {v}" for k, v in self._headers.items()]
        return "\r\n".join(lines) + "\r\n\r\n"

    def getHeader(self, name: str) -> str | None:      # noqa: N802 (ZAP naming)
        for k, v in self._headers.items():
            if k.lower() == name.lower():
                return v
        return None

    def setHeader(self, name: str, value: str) -> None:  # noqa: N802
        self._headers[name] = value


class ZapMessage:
    """
    Presents a ZAP HttpMessage-like interface over a Flow. Covers the accessors
    ZAP scripts use most. Method names intentionally match ZAP (camelCase).
    """
    def __init__(self, flow: Flow):
        self._flow = flow

    # --- request ---
    def getRequestHeader(self) -> _ZapHeader:          # noqa: N802
        r = self._flow.request
        start = f"{r.method} {r.url} HTTP/1.1"
        return _ZapHeader(start, r.headers)

    def getRequestBody(self):                          # noqa: N802
        return self._flow.request.body.decode(errors="replace")

    def setRequestBody(self, body: str) -> None:       # noqa: N802
        self._flow.request.body = body.encode()

    # --- response ---
    def getResponseHeader(self) -> _ZapHeader:         # noqa: N802
        resp = self._flow.response
        if resp is None:
            return _ZapHeader("HTTP/1.1 000", {})
        return _ZapHeader(f"HTTP/1.1 {resp.status}", resp.headers)

    def getResponseBody(self):                         # noqa: N802
        resp = self._flow.response
        return resp.body.decode(errors="replace") if resp else ""

    def setResponseBody(self, body: str) -> None:      # noqa: N802
        if self._flow.response:
            self._flow.response.body = body.encode()

    # --- convenience some scripts use ---
    def getRequestURL(self):                           # noqa: N802
        return self._flow.request.url


class _ZapPassiveScanContext:
    """
    Stand-in for ZAP's PluginPassiveScanner (the `ps` arg). ZAP scripts call
    ps.raiseAlert(...) / ps.newAlert()... to report. We translate an alert into a
    tag + note on the flow — neutral surfacing, no attack behaviour.
    """
    def __init__(self, flow: Flow):
        self._flow = flow

    def raiseAlert(self, risk=0, confidence=0, name="", *args, **kwargs):  # noqa: N802
        self._flow.tag("zap-alert")
        self._flow.note(f"ZAP alert: {name} (risk={risk}, confidence={confidence})")

    # ZAP's newer fluent alert builder — minimal support
    def newAlert(self):                                # noqa: N802
        return _ZapAlertBuilder(self._flow)


class _ZapAlertBuilder:
    def __init__(self, flow: Flow):
        self._flow = flow
        self._name = ""
    def setName(self, n):                              # noqa: N802
        self._name = n; return self
    def setRisk(self, r):  return self                 # noqa: N802
    def setConfidence(self, c):  return self           # noqa: N802
    def setDescription(self, d):  return self          # noqa: N802
    def raise_(self):
        self._flow.tag("zap-alert")
        self._flow.note(f"ZAP alert: {self._name}")
    # ZAP uses .raise() which is a Python keyword; provide both
    raise_alert = raise_


def run_zap_passive_script(scan_fn: Callable, flow: Flow) -> None:
    """
    Call a ZAP-style passive script's `scan(ps, msg, src)` entry point with
    shimmed objects bound to `flow`. `src` (the source HTML tree) is passed as
    None — scripts that need it can be adapted.
    """
    ps = _ZapPassiveScanContext(flow)
    msg = ZapMessage(flow)
    scan_fn(ps, msg, None)


# ---------------------------------------------------------------------------
# Burp-style shim
# ---------------------------------------------------------------------------

class BurpRequestResponse:
    """
    Presents a Burp IHttpRequestResponse-like interface over a Flow. Covers the
    common accessors Burp (Jython/Montoya-Python) scripts use. Bytes-oriented,
    like Burp.
    """
    def __init__(self, flow: Flow):
        self._flow = flow

    def getRequest(self) -> bytes:                     # noqa: N802
        r = self._flow.request
        head = f"{r.method} {r.url} HTTP/1.1\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in r.headers.items())
        return (head + "\r\n").encode() + r.body

    def getResponse(self) -> bytes:                    # noqa: N802
        resp = self._flow.response
        if resp is None:
            return b""
        head = f"HTTP/1.1 {resp.status}\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in resp.headers.items())
        return (head + "\r\n").encode() + resp.body

    def getUrl(self):                                  # noqa: N802
        return self._flow.request.url

    def getHttpService(self):                          # noqa: N802
        return _BurpHttpService(self._flow.request)

    # some scripts annotate via comment/highlight — map to our tag/note
    def setComment(self, comment: str) -> None:        # noqa: N802
        self._flow.note(f"burp-comment: {comment}")

    def setHighlight(self, colour: str) -> None:       # noqa: N802
        self._flow.tag(f"burp-highlight:{colour}")


class _BurpHttpService:
    def __init__(self, request: Request):
        from urllib.parse import urlparse
        p = urlparse(request.url)
        self._host = p.hostname or ""
        self._port = p.port or (443 if p.scheme == "https" else 80)
        self._proto = p.scheme or "http"
    def getHost(self):  return self._host              # noqa: N802
    def getPort(self):  return self._port              # noqa: N802
    def getProtocol(self):  return self._proto         # noqa: N802


def run_burp_passive_script(process_fn: Callable, flow: Flow) -> None:
    """
    Call a Burp-style passive check with a shimmed IHttpRequestResponse. Burp
    scripts vary; a common shape is a function taking the request/response
    wrapper. Adapt the binding to the specific script as needed.
    """
    rr = BurpRequestResponse(flow)
    process_fn(rr)


# ---------------------------------------------------------------------------
# Module wrappers — run a ported script as a platform module
# ---------------------------------------------------------------------------

class ZapScriptModule(BaseModule):
    """
    Wrap a ZAP-style passive `scan(ps, msg, src)` function as a platform module,
    so it runs in the normal pipeline. You provide the scan function (imported or
    pasted from the ZAP script you're porting).
    """
    def __init__(self, scan_fn: Callable, name: str = "zap-script"):
        self.name = name
        self._scan_fn = scan_fn

    def on_response(self, flow: Flow) -> None:
        run_zap_passive_script(self._scan_fn, flow)


class BurpScriptModule(BaseModule):
    """Wrap a Burp-style passive check function as a platform module."""
    def __init__(self, process_fn: Callable, name: str = "burp-script"):
        self.name = name
        self._process_fn = process_fn

    def on_response(self, flow: Flow) -> None:
        run_burp_passive_script(self._process_fn, flow)
