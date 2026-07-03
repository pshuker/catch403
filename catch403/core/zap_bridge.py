"""
ZAP bridge — drive OWASP ZAP's scanner from this platform and ingest results.

The legitimate route to Burp-class capability: your platform is the hub, ZAP's
mature open-source engine does the active scanning, and findings come back into
your Flow/History model so everything lives in one place and your modules can act
on them.

This talks to ZAP's REST API (the daemon ZAP exposes on localhost, default
:8080, with an API key). It does NOT reimplement scanning — it orchestrates the
engine the security community already built and trusts, and normalises ZAP's
alerts into this platform's Finding objects.

Design:
  * ZapClient        — thin REST client for ZAP's API (spider, ascan, alerts,
    core). Transport is injectable so this is testable offline; the default does
    real HTTP to the local ZAP daemon.
  * Finding          — a normalised vulnerability finding (ZAP alert -> our model)
  * ZapScanner       — high-level orchestration: spider a target, run the active
    scan, poll progress, collect findings. Authorised targets only.
  * findings_to_flows — fold ZAP findings into the platform History as flows,
    so scan results and proxied traffic share one view.

NOTE: ZAP must be installed and running as a daemon separately (it's a Java app);
this bridge assumes a reachable ZAP API endpoint. Network is disabled in this
build environment, so the client is unit-tested against a mock transport; point
it at a real ZAP daemon on your machine to use it live.

RESPONSIBLE USE: active scanning sends real traffic to a target. Only scan
systems you own or are explicitly authorised to test.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlencode

from core.flow import Request, Response, Flow


# ---------------------------------------------------------------------------
# normalised finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A vulnerability finding, normalised from a ZAP alert."""
    name: str
    risk: str                      # Informational | Low | Medium | High
    confidence: str
    url: str
    param: str = ""
    evidence: str = ""
    description: str = ""
    solution: str = ""
    cwe: int = 0
    reference: str = ""

    @classmethod
    def from_zap_alert(cls, a: dict) -> "Finding":
        return cls(
            name=a.get("alert", a.get("name", "")),
            risk=a.get("risk", ""),
            confidence=a.get("confidence", ""),
            url=a.get("url", ""),
            param=a.get("param", ""),
            evidence=a.get("evidence", ""),
            description=a.get("description", ""),
            solution=a.get("solution", ""),
            cwe=int(a.get("cweid", 0) or 0),
            reference=a.get("reference", ""),
        )


# ---------------------------------------------------------------------------
# ZAP REST client
# ---------------------------------------------------------------------------

class ZapClient:
    """
    Thin client for ZAP's REST API. Every ZAP API call is an HTTP GET to
    http://<host>:<port>/JSON/<component>/<action>/?apikey=...&params. Transport
    is injectable (url -> dict) so logic is testable without a live ZAP.
    """
    def __init__(self, host: str = "127.0.0.1", port: int = 8080,
                 api_key: str = "", transport: Callable[[str], dict] | None = None,
                 timeout: float = 30.0):
        self.base = f"http://{host}:{port}"
        self.api_key = api_key
        self.timeout = timeout
        self._transport = transport or self._http_get

    def _http_get(self, url: str) -> dict:
        import urllib.request
        with urllib.request.urlopen(url, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode())

    def _call(self, component: str, action: str, **params) -> dict:
        q = {"apikey": self.api_key, **params}
        url = f"{self.base}/JSON/{component}/action/{action}/?{urlencode(q)}"
        return self._transport(url)

    def _view(self, component: str, view: str, **params) -> dict:
        q = {"apikey": self.api_key, **params}
        url = f"{self.base}/JSON/{component}/view/{view}/?{urlencode(q)}"
        return self._transport(url)

    # --- spider (crawl to discover content) ---
    def spider_scan(self, target: str) -> str:
        return self._call("spider", "scan", url=target).get("scan", "")

    def spider_status(self, scan_id: str) -> int:
        return int(self._view("spider", "status", scanId=scan_id).get("status", 0))

    # --- active scan ---
    def ascan_scan(self, target: str) -> str:
        return self._call("ascan", "scan", url=target).get("scan", "")

    def ascan_status(self, scan_id: str) -> int:
        return int(self._view("ascan", "status", scanId=scan_id).get("status", 0))

    # --- results ---
    def alerts(self, base_url: str = "") -> list[dict]:
        params = {"baseurl": base_url} if base_url else {}
        return self._view("core", "alerts", **params).get("alerts", [])

    def version(self) -> str:
        return self._view("core", "version").get("version", "")


# ---------------------------------------------------------------------------
# high-level orchestration
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    spider_done: bool = False
    ascan_done: bool = False
    error: str = ""

    def by_risk(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.risk or "Unknown", []).append(f)
        return out

    def summary(self) -> str:
        counts = {r: len(fs) for r, fs in self.by_risk().items()}
        return f"{self.target}: {len(self.findings)} findings {counts}"


class ZapScanner:
    """
    Orchestrates a full ZAP scan of an authorised target: spider -> active scan ->
    collect findings. Polls status with a bounded number of attempts so it can't
    hang forever. `poll_interval`/`max_polls` are tunable (and tiny in tests).
    """
    def __init__(self, client: ZapClient, poll_interval: float = 2.0,
                 max_polls: int = 300):
        self.client = client
        self.poll_interval = poll_interval
        self.max_polls = max_polls

    def _wait(self, status_fn: Callable[[str], int], scan_id: str) -> bool:
        """Poll a ZAP scan's status until 100% or bound reached."""
        for _ in range(self.max_polls):
            if status_fn(scan_id) >= 100:
                return True
            time.sleep(self.poll_interval)
        return False

    def scan(self, target: str, *, spider: bool = True) -> ScanResult:
        result = ScanResult(target=target)
        try:
            if spider:
                sid = self.client.spider_scan(target)
                result.spider_done = self._wait(self.client.spider_status, sid)
            aid = self.client.ascan_scan(target)
            result.ascan_done = self._wait(self.client.ascan_status, aid)
            alerts = self.client.alerts(target)
            result.findings = [Finding.from_zap_alert(a) for a in alerts]
        except Exception as e:  # noqa: BLE001 — surface engine/transport errors
            result.error = str(e)
        return result


# ---------------------------------------------------------------------------
# fold findings into the platform's Flow/History model
# ---------------------------------------------------------------------------

def findings_to_flows(result: ScanResult) -> list[Flow]:
    """
    Represent each finding as a Flow so scan results live alongside proxied
    traffic in History, and modules/UI can treat them uniformly. The flow's
    request is the affected URL; the finding detail rides in tags/notes/meta.
    """
    flows: list[Flow] = []
    for f in result.findings:
        req = Request("GET", f.url or f"http://{result.target}")
        flow = Flow(request=req)
        flow.tag("zap-finding")
        flow.tag(f"risk:{f.risk.lower()}" if f.risk else "risk:unknown")
        flow.note(f"{f.name} [{f.risk}/{f.confidence}]"
                  + (f" param={f.param}" if f.param else ""))
        flow.meta["finding"] = {
            "name": f.name, "risk": f.risk, "confidence": f.confidence,
            "url": f.url, "param": f.param, "evidence": f.evidence,
            "cwe": f.cwe, "solution": f.solution,
        }
        flows.append(flow)
    return flows
