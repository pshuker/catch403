"""
Example module: insecure-transmission inspector (passive, neutral).

Flags requests that carry sensitive data (auth headers, cookies, tokens, or
password-like form fields) over plaintext HTTP rather than HTTPS. This is pure
observation — it sends nothing and attacks nothing — the kind of finding that's
useful during an authorised review and safe to run anywhere.

Another template to copy: it reads requests, checks a simple condition, and
annotates the flow. Nothing here is active.
"""

from __future__ import annotations

import re

from core.modules import BaseModule
from core.flow import Flow


# header/field names that indicate something sensitive is being sent
SENSITIVE_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token")
SENSITIVE_FIELD = re.compile(rb"(password|passwd|pwd|secret|token|api[_-]?key)",
                             re.IGNORECASE)


class InsecureTransmissionInspector(BaseModule):
    name = "insecure-transmission-inspector"

    def on_request(self, flow: Flow) -> None:
        req = flow.request
        # only interesting when NOT over TLS
        if req.url.lower().startswith("https://"):
            return

        reasons = []
        for h in SENSITIVE_HEADERS:
            if req.header(h):
                reasons.append(f"{h} header")
        if req.body and SENSITIVE_FIELD.search(req.body):
            reasons.append("password/token-like field in body")

        if reasons:
            flow.tag("insecure-transmission")
            flow.add_finding(
                self.name,
                "Sensitive data sent over plaintext HTTP",
                severity="high",
                detail="; ".join(reasons))
