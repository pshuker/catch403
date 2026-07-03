"""
Flow — the HTTP request/response model that everything operates on.

A Flow is one intercepted HTTP exchange: the request, the (eventual) response,
and metadata. Modules receive Flow objects and may inspect or mutate them. This
is the central data structure of the platform — the equivalent of the item that
moves through Burp's proxy pipeline.

Deliberately dependency-free and simple: a module author should be able to read
this file and understand everything they can touch.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


@dataclass
class Request:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    @property
    def host(self) -> str:
        return urlparse(self.url).netloc

    @property
    def path(self) -> str:
        return urlparse(self.url).path or "/"

    @property
    def query(self) -> dict[str, list[str]]:
        return parse_qs(urlparse(self.url).query)

    def set_query(self, params: dict[str, str]) -> None:
        """Replace the query string from a flat dict."""
        parts = list(urlparse(self.url))
        parts[4] = urlencode(params)
        self.url = urlunparse(parts)

    def header(self, name: str, default: str = "") -> str:
        """Case-insensitive header lookup."""
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default

    def set_header(self, name: str, value: str) -> None:
        for k in list(self.headers):
            if k.lower() == name.lower():
                self.headers[k] = value
                return
        self.headers[name] = value

    def clone(self) -> "Request":
        return Request(self.method, self.url, dict(self.headers), self.body)


@dataclass
class Response:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def header(self, name: str, default: str = "") -> str:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default


@dataclass
class Finding:
    """
    A structured observation a module reports about a flow. Richer than a free-
    text note: it has a severity and a type, so findings can be sorted, filtered,
    counted, and shown in a UI the way a real tool presents results.

    Severity is advisory (info | low | medium | high) — passive inspection
    modules typically report info/low; the operator's own modules decide their
    own severities.
    """
    module: str                  # which module reported it
    title: str                   # short human summary
    severity: str = "info"       # info | low | medium | high
    detail: str = ""             # optional longer explanation

    def __str__(self) -> str:
        return f"[{self.severity}] {self.title} ({self.module})"


@dataclass
class Flow:
    """One HTTP exchange moving through the pipeline."""
    request: Request
    response: Response | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    ts: float = field(default_factory=time.time)
    # tags/notes let modules annotate a flow for the UI or other modules
    tags: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)
    # structured findings modules report (severity + type), for a real results view
    findings: list["Finding"] = field(default_factory=list)
    # set True by a module to drop the flow (do not forward)
    dropped: bool = False
    # arbitrary per-flow scratch space for modules to stash data
    meta: dict = field(default_factory=dict)

    def tag(self, label: str) -> None:
        self.tags.add(label)

    def note(self, text: str) -> None:
        self.notes.append(text)

    def add_finding(self, module: str, title: str, severity: str = "info",
                    detail: str = "") -> "Finding":
        """Report a structured finding on this flow (and tag it for filtering)."""
        f = Finding(module=module, title=title, severity=severity, detail=detail)
        self.findings.append(f)
        self.tag(f"finding:{severity}")
        return f

    def drop(self) -> None:
        self.dropped = True

    def summary(self) -> str:
        r = self.request
        code = self.response.status if self.response else "-"
        base = f"{r.method} {r.host}{r.path} -> {code}"
        if self.findings:
            base += f"  [{len(self.findings)} finding(s)]"
        return base
