"""
Repeater + Decoder — the manual-testing tools.

Repeater: take a captured request, modify it, send it again, inspect the
response. The core manual-testing loop (the equivalent of Burp's Repeater).

Decoder: the everyday transforms — URL, base64, hex, HTML entities — both ways.
Neutral utility; nothing here is offensive, it's format conversion.

The actual HTTP send is delegated to a transport callable so this stays testable
offline and doesn't hard-wire a networking choice.
"""

from __future__ import annotations

import base64
import html
import urllib.parse
from typing import Callable

from core.flow import Request, Response, Flow


class Repeater:
    """
    Resend individual requests with modifications. `transport` is a callable
    Request -> Response (real HTTP on your machine; a mock in tests), so the
    Repeater logic is independent of the networking layer.
    """
    def __init__(self, transport: Callable[[Request], Response]):
        self._transport = transport
        self.history: list[Flow] = []

    def send(self, request: Request) -> Flow:
        """Send a request and record the resulting flow."""
        flow = Flow(request=request.clone())
        try:
            flow.response = self._transport(request)
        except Exception as e:  # noqa: BLE001
            flow.note(f"repeater transport error: {e}")
        self.history.append(flow)
        return flow

    def resend_last(self) -> Flow | None:
        if not self.history:
            return None
        return self.send(self.history[-1].request)


class Decoder:
    """Two-way transforms for the formats you hit constantly while testing."""

    @staticmethod
    def url_encode(s: str) -> str:
        return urllib.parse.quote(s, safe="")

    @staticmethod
    def url_decode(s: str) -> str:
        return urllib.parse.unquote(s)

    @staticmethod
    def base64_encode(s: str) -> str:
        return base64.b64encode(s.encode()).decode()

    @staticmethod
    def base64_decode(s: str) -> str:
        # be lenient about missing padding
        pad = "=" * (-len(s) % 4)
        return base64.b64decode(s + pad).decode(errors="replace")

    @staticmethod
    def hex_encode(s: str) -> str:
        return s.encode().hex()

    @staticmethod
    def hex_decode(s: str) -> str:
        return bytes.fromhex(s).decode(errors="replace")

    @staticmethod
    def html_encode(s: str) -> str:
        return html.escape(s)

    @staticmethod
    def html_decode(s: str) -> str:
        return html.unescape(s)

    # a small registry so a UI can enumerate available transforms
    @classmethod
    def transforms(cls) -> dict[str, Callable[[str], str]]:
        return {
            "url-encode": cls.url_encode, "url-decode": cls.url_decode,
            "base64-encode": cls.base64_encode, "base64-decode": cls.base64_decode,
            "hex-encode": cls.hex_encode, "hex-decode": cls.hex_decode,
            "html-encode": cls.html_encode, "html-decode": cls.html_decode,
        }

    @classmethod
    def apply(cls, name: str, s: str) -> str:
        t = cls.transforms().get(name)
        if t is None:
            raise KeyError(f"unknown transform: {name}")
        return t(s)
