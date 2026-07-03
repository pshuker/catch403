"""
Example module: security-header inspector (passive, neutral).

A reference module showing how to write one. It only READS responses and
annotates them — no requests are sent, nothing is attacked. It flags responses
missing common security headers, the kind of passive observation that's safe and
useful during any authorised review.

Use this as a template for your own modules: subclass BaseModule, set a name,
implement the hooks you need. Drop your file in the modules/ directory (or load
it explicitly) and it hooks into the pipeline.
"""

from __future__ import annotations

from core.modules import BaseModule
from core.flow import Flow


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]


class SecurityHeaderInspector(BaseModule):
    name = "security-header-inspector"

    def on_response(self, flow: Flow) -> None:
        if flow.response is None:
            return
        missing = [h for h in SECURITY_HEADERS
                   if not flow.response.header(h)]
        if missing:
            flow.tag("missing-security-headers")
            flow.note(f"missing security headers: {', '.join(missing)}")
