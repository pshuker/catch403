"""Tests for the proxy platform foundation."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_passed = 0
_failed = 0


def check(desc, ok):
    global _passed, _failed
    if ok:
        _passed += 1
        print(f"  PASS  {desc}")
    else:
        _failed += 1
        print(f"  FAIL  {desc}")


# --- flow model -------------------------------------------------------------

def test_request_parsing():
    from core.flow import Request
    r = Request("GET", "https://example.com/api/users?id=5&sort=name")
    check("request parses host/path/query",
          r.host == "example.com" and r.path == "/api/users"
          and r.query["id"] == ["5"])


def test_request_header_case_insensitive():
    from core.flow import Request
    r = Request("GET", "https://x.com/", {"Content-Type": "application/json"})
    r.set_header("content-type", "text/html")   # should update, not duplicate
    check("header lookup/set is case-insensitive",
          r.header("CONTENT-TYPE") == "text/html" and len(r.headers) == 1)


def test_request_set_query():
    from core.flow import Request
    r = Request("GET", "https://x.com/search?q=old")
    r.set_query({"q": "new", "page": "2"})
    check("set_query rewrites the query string",
          r.query["q"] == ["new"] and r.query["page"] == ["2"])


def test_flow_annotation():
    from core.flow import Request, Flow
    f = Flow(request=Request("GET", "https://x.com/"))
    f.tag("interesting"); f.note("saw something"); 
    check("flow can be tagged and noted",
          "interesting" in f.tags and f.notes == ["saw something"])


def test_flow_drop():
    from core.flow import Request, Flow
    f = Flow(request=Request("GET", "https://x.com/"))
    f.drop()
    check("flow can be dropped", f.dropped is True)


# --- module system ----------------------------------------------------------

def test_module_hooks_run():
    from core.modules import ModuleManager, BaseModule
    from core.flow import Request, Flow
    seen = {"req": 0, "resp": 0}
    class M(BaseModule):
        name = "counter"
        def on_request(self, flow): seen["req"] += 1
        def on_response(self, flow): seen["resp"] += 1
    mgr = ModuleManager(); mgr.add(M())
    f = Flow(request=Request("GET", "https://x.com/"))
    mgr.run_request(f); mgr.run_response(f)
    check("module request/response hooks fire",
          seen["req"] == 1 and seen["resp"] == 1)


def test_module_can_mutate_flow():
    from core.modules import ModuleManager, BaseModule
    from core.flow import Request, Flow
    class Injector(BaseModule):
        name = "injector"
        def on_request(self, flow):
            flow.request.set_header("X-Test", "added")
    mgr = ModuleManager(); mgr.add(Injector())
    f = Flow(request=Request("GET", "https://x.com/"))
    mgr.run_request(f)
    check("module can mutate a request", f.request.header("X-Test") == "added")


def test_module_can_drop_flow():
    from core.modules import ModuleManager, BaseModule
    from core.flow import Request, Flow
    class Blocker(BaseModule):
        name = "blocker"
        def on_request(self, flow): flow.drop()
    ran_after = {"v": False}
    class After(BaseModule):
        name = "after"
        def on_request(self, flow): ran_after["v"] = True
    mgr = ModuleManager(); mgr.add(Blocker()); mgr.add(After())
    f = Flow(request=Request("GET", "https://x.com/"))
    mgr.run_request(f)
    check("a dropped flow halts the module chain",
          f.dropped is True and ran_after["v"] is False)


def test_module_error_does_not_crash():
    from core.modules import ModuleManager, BaseModule
    from core.flow import Request, Flow
    class Bad(BaseModule):
        name = "bad"
        def on_request(self, flow): raise RuntimeError("boom")
    mgr = ModuleManager(); mgr.add(Bad())
    f = Flow(request=Request("GET", "https://x.com/"))
    mgr.run_request(f)   # must not raise
    check("a misbehaving module is caught, not fatal",
          len(mgr.errors) == 1 and "boom" in mgr.errors[0])


def test_module_load_from_file():
    from core.modules import ModuleManager
    mgr = ModuleManager()
    loaded = mgr.load_file(os.path.join(
        os.path.dirname(__file__), "modules", "security_headers.py"))
    check("modules load from a file (the extend-via-file path)",
          "security-header-inspector" in loaded)


def test_example_module_flags_missing_headers():
    from core.modules import ModuleManager
    from core.flow import Request, Response, Flow
    mgr = ModuleManager()
    mgr.load_file(os.path.join(
        os.path.dirname(__file__), "modules", "security_headers.py"))
    f = Flow(request=Request("GET", "https://x.com/"),
             response=Response(200, {}))   # no security headers
    mgr.run_response(f)
    check("example module flags missing security headers",
          "missing-security-headers" in f.tags)


# --- repeater + decoder -----------------------------------------------------

def test_repeater_sends_and_records():
    from core.tools import Repeater
    from core.flow import Request, Response
    def transport(req): return Response(200, {}, b"ok")
    rep = Repeater(transport)
    flow = rep.send(Request("GET", "https://x.com/"))
    check("repeater sends and records the flow",
          flow.response.status == 200 and len(rep.history) == 1)


def test_repeater_resend():
    from core.tools import Repeater
    from core.flow import Request, Response
    calls = {"n": 0}
    def transport(req):
        calls["n"] += 1; return Response(200)
    rep = Repeater(transport)
    rep.send(Request("POST", "https://x.com/a"))
    rep.resend_last()
    check("repeater can resend the last request", calls["n"] == 2)


def test_decoder_roundtrips():
    from core.tools import Decoder
    s = "hello world & <friends>"
    check("decoder transforms round-trip",
          Decoder.url_decode(Decoder.url_encode(s)) == s
          and Decoder.base64_decode(Decoder.base64_encode(s)) == s
          and Decoder.hex_decode(Decoder.hex_encode(s)) == s
          and Decoder.html_decode(Decoder.html_encode(s)) == s)


def test_decoder_registry():
    from core.tools import Decoder
    check("decoder exposes a transform registry",
          "base64-encode" in Decoder.transforms()
          and Decoder.apply("url-encode", "a b") == "a%20b")


# --- intercept + history ----------------------------------------------------

def test_intercept_hold_forward_drop():
    from core.intercept import InterceptQueue
    from core.flow import Request, Flow
    q = InterceptQueue(enabled=True)
    f1 = Flow(request=Request("GET", "https://x.com/1"))
    f2 = Flow(request=Request("GET", "https://x.com/2"))
    q.hold(f1); q.hold(f2)
    fwd = q.forward(f1.id)
    dropped = q.drop(f2.id)
    check("intercept queue holds, forwards, and drops",
          fwd is f1 and dropped.dropped is True and q.pending() == [])


def test_intercept_toggle():
    from core.intercept import InterceptQueue
    q = InterceptQueue()
    check("intercept toggles on/off",
          q.toggle(True) is True and q.toggle(False) is False)


def test_history_filter():
    from core.intercept import History
    from core.flow import Request, Response, Flow
    h = History()
    a = Flow(request=Request("GET", "https://api.x.com/"),
             response=Response(200))
    b = Flow(request=Request("POST", "https://web.y.com/"),
             response=Response(404))
    h.add(a); h.add(b)
    check("history filters by host/method/status",
          h.filter(method="GET") == [a]
          and h.filter(status=404) == [b]
          and h.filter(host="api") == [a])


# --- compatibility layer (ZAP / Burp script shims) --------------------------

def test_zap_message_shim():
    from core.compat import ZapMessage
    from core.flow import Request, Response, Flow
    f = Flow(request=Request("POST", "https://x.com/", {"Content-Type": "application/json"},
                             b'{"a":1}'),
             response=Response(200, {"Server": "nginx"}, b"body"))
    msg = ZapMessage(f)
    check("ZAP message shim exposes ZAP-style accessors",
          msg.getRequestBody() == '{"a":1}'
          and msg.getResponseBody() == "body"
          and msg.getResponseHeader().getHeader("server") == "nginx")


def test_zap_passive_script_runs_unmodified():
    from core.compat import run_zap_passive_script
    from core.flow import Request, Response, Flow
    # a script written to ZAP's real passive-script API
    def scan(ps, msg, src):
        if "error" in msg.getResponseBody().lower():
            ps.raiseAlert(risk=1, confidence=2, name="Error in response")
    f = Flow(request=Request("GET", "https://x.com/"),
             response=Response(200, {}, b"<html>Internal error</html>"))
    run_zap_passive_script(scan, f)
    check("a ZAP passive script runs unmodified via the shim",
          "zap-alert" in f.tags and any("Error in response" in n for n in f.notes))


def test_burp_requestresponse_shim():
    from core.compat import BurpRequestResponse
    from core.flow import Request, Response, Flow
    f = Flow(request=Request("GET", "https://x.com:8443/p"),
             response=Response(200, {"X-Test": "1"}, b"ok"))
    rr = BurpRequestResponse(f)
    svc = rr.getHttpService()
    check("Burp request/response shim exposes Burp-style accessors",
          b"GET https://x.com:8443/p" in rr.getRequest()
          and b"ok" in rr.getResponse()
          and svc.getHost() == "x.com" and svc.getPort() == 8443
          and svc.getProtocol() == "https")


def test_burp_passive_script_runs_unmodified():
    from core.compat import run_burp_passive_script
    from core.flow import Request, Response, Flow
    def check_fn(rr):
        if b"Server:" in rr.getResponse():
            rr.setComment("server disclosed")
            rr.setHighlight("red")
    f = Flow(request=Request("GET", "https://x.com/"),
             response=Response(200, {"Server": "apache"}, b"x"))
    run_burp_passive_script(check_fn, f)
    check("a Burp passive script runs unmodified via the shim",
          any("server disclosed" in n for n in f.notes)
          and "burp-highlight:red" in f.tags)


def test_ported_scripts_as_modules():
    from core.compat import ZapScriptModule, BurpScriptModule
    from core.modules import ModuleManager
    from core.flow import Request, Response, Flow
    def zap_scan(ps, msg, src):
        if msg.getResponseHeader().getHeader("Content-Type"):
            ps.raiseAlert(name="has content-type")
    def burp_fn(rr):
        rr.setHighlight("green")
    mgr = ModuleManager()
    mgr.add(ZapScriptModule(zap_scan, name="z"))
    mgr.add(BurpScriptModule(burp_fn, name="b"))
    f = Flow(request=Request("GET", "https://x.com/"),
             response=Response(200, {"Content-Type": "text/html"}, b"x"))
    mgr.run_response(f)
    check("ported ZAP+Burp scripts run as pipeline modules",
          mgr.list_modules() == ["z", "b"]
          and "zap-alert" in f.tags and "burp-highlight:green" in f.tags)


# --- ZAP bridge (drive ZAP's scanner, ingest findings) ----------------------

def _mock_zap():
    def transport(url):
        if "/spider/action/scan/" in url: return {"scan": "1"}
        if "/spider/view/status/" in url: return {"status": "100"}
        if "/ascan/action/scan/" in url: return {"scan": "2"}
        if "/ascan/view/status/" in url: return {"status": "100"}
        if "/core/view/alerts/" in url:
            return {"alerts": [
                {"alert": "SQL Injection", "risk": "High", "confidence": "Medium",
                 "url": "http://t/x?id=1", "param": "id", "cweid": "89",
                 "evidence": "err"},
                {"alert": "Missing CSP", "risk": "Low", "confidence": "High",
                 "url": "http://t/", "cweid": "693"}]}
        if "/core/view/version/" in url: return {"version": "2.15.0"}
        return {}
    return transport


def test_zap_client_api_calls():
    from core.zap_bridge import ZapClient
    c = ZapClient(api_key="k", transport=_mock_zap())
    check("ZAP client makes correct API calls",
          c.version() == "2.15.0" and c.spider_scan("http://t") == "1"
          and c.ascan_scan("http://t") == "2")


def test_zap_finding_normalisation():
    from core.zap_bridge import Finding
    f = Finding.from_zap_alert({"alert": "XSS", "risk": "High",
                                "confidence": "Medium", "url": "http://t/",
                                "param": "q", "cweid": "79"})
    check("ZAP alert normalises to a Finding",
          f.name == "XSS" and f.risk == "High" and f.cwe == 79 and f.param == "q")


def test_zap_scanner_orchestration():
    from core.zap_bridge import ZapClient, ZapScanner
    scanner = ZapScanner(ZapClient(api_key="k", transport=_mock_zap()),
                         poll_interval=0, max_polls=5)
    r = scanner.scan("http://t")
    check("ZAP scanner orchestrates spider+ascan and collects findings",
          r.spider_done and r.ascan_done and len(r.findings) == 2
          and r.by_risk()["High"][0].name == "SQL Injection")


def test_zap_findings_to_flows():
    from core.zap_bridge import ZapClient, ZapScanner, findings_to_flows
    from core.intercept import History
    scanner = ZapScanner(ZapClient(api_key="k", transport=_mock_zap()),
                         poll_interval=0, max_polls=5)
    r = scanner.scan("http://t")
    flows = findings_to_flows(r)
    h = History()
    for fl in flows:
        h.add(fl)
    check("ZAP findings fold into the Flow/History model",
          len(flows) == 2 and len(h.filter(tag="zap-finding")) == 2
          and len(h.filter(tag="risk:high")) == 1
          and flows[0].meta["finding"]["name"] == "SQL Injection")


def test_zap_scanner_bounded_polling():
    from core.zap_bridge import ZapClient, ZapScanner
    # a scan that never completes must not hang — bounded polls
    def stuck(url):
        if "action/scan" in url: return {"scan": "1"}
        if "view/status" in url: return {"status": "10"}   # never reaches 100
        if "view/alerts" in url: return {"alerts": []}
        return {}
    scanner = ZapScanner(ZapClient(transport=stuck), poll_interval=0, max_polls=3)
    r = scanner.scan("http://t", spider=False)
    check("ZAP scanner polling is bounded (cannot hang forever)",
          r.ascan_done is False)


def test_flow_structured_findings():
    from core.flow import Flow, Request, Finding
    f = Flow(Request("GET", "http://x.com/"))
    finding = f.add_finding("mod", "Something", severity="high", detail="d")
    check("flow.add_finding records a structured finding + severity tag",
          isinstance(finding, Finding) and len(f.findings) == 1
          and "finding:high" in f.tags and f.findings[0].severity == "high")


def test_insecure_transmission_module():
    from core.flow import Flow, Request
    from modules.insecure_transmission import InsecureTransmissionInspector
    m = InsecureTransmissionInspector()
    # plaintext + auth header -> high finding
    f = Flow(Request("POST", "http://x.com/login",
                     {"Authorization": "Bearer z"}, b"password=hunter2"))
    m.on_request(f)
    # same over https -> nothing
    f2 = Flow(Request("POST", "https://x.com/login",
                      {"Authorization": "Bearer z"}))
    m.on_request(f2)
    check("insecure-transmission module flags plaintext secrets, ignores HTTPS",
          len(f.findings) == 1 and f.findings[0].severity == "high"
          and len(f2.findings) == 0)


def test_sensitive_data_module():
    from core.flow import Flow, Request, Response
    from modules.sensitive_data import SensitiveDataInspector
    m = SensitiveDataInspector()
    f = Flow(Request("GET", "https://x.com/c"),
             Response(200, {}, b"user admin@corp.com key AKIAIOSFODNN7EXAMPLE"))
    m.on_response(f)
    check("sensitive-data module detects PII/keys in responses",
          len(f.findings) == 1 and f.findings[0].severity == "medium")


def test_history_findings_aggregation():
    from core.flow import Flow, Request
    from core.intercept import History
    h = History()
    f1 = Flow(Request("GET", "http://a.com/"))
    f1.add_finding("m", "high one", severity="high")
    f2 = Flow(Request("GET", "http://b.com/"))
    f2.add_finding("m", "low one", severity="low")
    h.add(f1); h.add(f2)
    summary = h.findings_summary()
    highs = h.findings(severity="high")
    check("history aggregates findings across flows with severity counts",
          summary.get("high") == 1 and summary.get("low") == 1
          and len(highs) == 1 and len(h.findings()) == 2)


def run():
    print("proxy platform foundation tests\n")
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
            except Exception as e:
                global _failed
                _failed += 1
                print(f"  FAIL  {name} CRASHED: {e}")
    print(f"\n{_passed} passed, {_failed} failed")
    sys.exit(1 if _failed else 0)


if __name__ == "__main__":
    run()
