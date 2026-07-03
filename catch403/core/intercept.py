"""
Intercept + History — the proxy pipeline state.

Intercept: a hold queue. When intercept is ON, flows pause here for the operator
to forward, edit-then-forward, or drop — the manual gate Burp's Proxy tab gives
you. When OFF, flows pass straight through (modules still run).

History: an append-only log of every flow seen, with simple filtering, so you can
review and re-send past traffic.

This module is the state; the actual proxy server wires it to a transport. Kept
transport-agnostic and dependency-free so it's testable without a live socket.
"""

from __future__ import annotations

from core.flow import Flow


class InterceptQueue:
    """Holds flows awaiting an operator decision when intercept is enabled."""
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self._held: list[Flow] = []

    def toggle(self, on: bool | None = None) -> bool:
        self.enabled = (not self.enabled) if on is None else on
        return self.enabled

    def hold(self, flow: Flow) -> None:
        self._held.append(flow)

    def pending(self) -> list[Flow]:
        return list(self._held)

    def forward(self, flow_id: str) -> Flow | None:
        """Release a held flow to be sent."""
        for f in list(self._held):
            if f.id == flow_id:
                self._held.remove(f)
                return f
        return None

    def drop(self, flow_id: str) -> Flow | None:
        for f in list(self._held):
            if f.id == flow_id:
                self._held.remove(f)
                f.drop()
                return f
        return None

    def forward_all(self) -> list[Flow]:
        out = list(self._held)
        self._held.clear()
        return out


class History:
    """Append-only record of flows, with light filtering."""
    def __init__(self, cap: int = 10000):
        self.cap = cap
        self._flows: list[Flow] = []

    def add(self, flow: Flow) -> None:
        self._flows.append(flow)
        if len(self._flows) > self.cap:
            self._flows.pop(0)

    def all(self) -> list[Flow]:
        return list(self._flows)

    def filter(self, *, host: str | None = None, method: str | None = None,
               status: int | None = None, tag: str | None = None) -> list[Flow]:
        out = self._flows
        if host is not None:
            out = [f for f in out if host.lower() in f.request.host.lower()]
        if method is not None:
            out = [f for f in out if f.request.method == method.upper()]
        if status is not None:
            out = [f for f in out if f.response and f.response.status == status]
        if tag is not None:
            out = [f for f in out if tag in f.tags]
        return list(out)

    def get(self, flow_id: str) -> Flow | None:
        for f in self._flows:
            if f.id == flow_id:
                return f
        return None

    def findings(self, severity: str | None = None) -> list:
        """
        All structured findings across recorded flows, newest first — the
        platform's results view. Optionally filter to one severity. Each entry
        pairs the finding with the flow it came from so a UI can link back.
        """
        out = []
        for f in reversed(self._flows):
            for finding in f.findings:
                if severity is None or finding.severity == severity:
                    out.append({"flow_id": f.id, "flow": f.summary(),
                                "finding": finding})
        return out

    def findings_summary(self) -> dict[str, int]:
        """Count of findings by severity across all flows (for a dashboard)."""
        counts: dict[str, int] = {}
        for f in self._flows:
            for finding in f.findings:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts
