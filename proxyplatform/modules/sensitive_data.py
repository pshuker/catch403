"""
Example module: sensitive-data-in-response inspector (passive, neutral).

Scans response bodies for patterns that suggest sensitive data is being exposed
— email addresses, what look like API keys/tokens, private key headers, or common
cloud-credential formats. It only READS responses and annotates them; it never
sends a request or attacks anything.

This is the kind of passive DLP-style observation that's safe during an
authorised review and helps spot accidental data exposure. Copy it as a template
for your own passive analysers.
"""

from __future__ import annotations

import re

from core.modules import BaseModule
from core.flow import Flow


# lightweight, well-known indicators — deliberately conservative to limit noise
PATTERNS = {
    "email-address": re.compile(rb"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "private-key-block": re.compile(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "aws-access-key-id": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "bearer-token": re.compile(rb"[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}"),
    "jwt-like": re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}


class SensitiveDataInspector(BaseModule):
    name = "sensitive-data-inspector"

    def on_response(self, flow: Flow) -> None:
        if flow.response is None or not flow.response.body:
            return
        body = flow.response.body
        found = []
        for label, pat in PATTERNS.items():
            hits = pat.findall(body)
            if hits:
                found.append(f"{label} (x{len(hits)})")
        if found:
            flow.tag("sensitive-data-exposure")
            flow.add_finding(
                self.name,
                "Possible sensitive data exposed in response",
                severity="medium",
                detail=", ".join(found))
