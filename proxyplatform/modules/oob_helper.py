#!/usr/bin/python3
"""
OOB (Out-of-Band) Interaction Helper — Burp Collaborator alternative.

Provides a free, self-contained OOB detection layer using:
  1. ProjectDiscovery interactsh (https://interactsh.com) — free public server
  2. Self-hosted interactsh server (if you have one)
  3. Simple DNS-based probing via dnslog.cn / canarytokens

Features:
  - Generate unique per-payload canary tokens
  - Poll interactsh for DNS/HTTP interactions
  - Correlate interactions back to specific payloads/requests
  - Use as a drop-in replacement for Burp Collaborator in SSRF, XXE, blind XSS

Usage:
  # Interactive session
  ../.venv/bin/python3 modules/oob_helper.py --start
  ../.venv/bin/python3 modules/oob_helper.py --poll
  ../.venv/bin/python3 modules/oob_helper.py --token mytest --generate

  # As a library (in other modules)
  from modules.oob_helper import OOBSession
  oob = OOBSession()
  token = oob.new_token("ssrf-probe")
  payload_url = oob.url(token)      # http://<token>.oob.catch403.local/
  ... inject payload_url into target ...
  hits = oob.poll(token)            # returns list of interaction dicts
"""
import argparse
import hashlib
import json
import os
import time
import uuid
import urllib.parse

import requests
import urllib3

from core.colors import bold, end, good, bad, info, run

urllib3.disable_warnings()

TIMEOUT = 10

# ── interactsh client ─────────────────────────────────────────────────────

INTERACTSH_SERVER = "https://oast.pro"  # ProjectDiscovery public instance
# Alternatives: oast.live, oast.me, oast.online, oast.fun, oast.site

_CONFIG_DIR  = os.path.expanduser("~/.proxyplatform")
_SESSION_FILE = os.path.join(_CONFIG_DIR, "oob_session.json")


class InteractshError(Exception):
    pass


class OOBSession:
    """
    Manages an interactsh session for OOB detection.

    One session = one interactsh subdomain (e.g. abc123.oast.pro)
    Each unique test gets a sub-prefix: ssrf-probe.abc123.oast.pro
    Poll the session to retrieve all interactions.
    """

    def __init__(self, server: str = INTERACTSH_SERVER, secret: str = ""):
        self._server = server.rstrip("/")
        self._secret = secret or self._load_secret()
        self._correlation_id: str = ""
        self._host: str = ""
        self._tokens: dict[str, dict] = {}  # token → {label, created_at}

    # ── session lifecycle ─────────────────────────────────────────────────

    def _load_secret(self) -> str:
        try:
            if os.path.isfile(_SESSION_FILE):
                with open(_SESSION_FILE) as fh:
                    return json.load(fh).get("secret", "")
        except Exception:
            pass
        return ""

    def _save_state(self):
        os.makedirs(_CONFIG_DIR, exist_ok=True)
        with open(_SESSION_FILE, "w") as fh:
            json.dump({
                "server":         self._server,
                "secret":         self._secret,
                "correlation_id": self._correlation_id,
                "host":           self._host,
                "tokens":         self._tokens,
            }, fh, indent=2)

    @classmethod
    def load(cls) -> "OOBSession | None":
        """Load a saved session from disk."""
        try:
            with open(_SESSION_FILE) as fh:
                state = json.load(fh)
            sess = cls(state.get("server", INTERACTSH_SERVER),
                       state.get("secret", ""))
            sess._correlation_id = state.get("correlation_id", "")
            sess._host           = state.get("host", "")
            sess._tokens         = state.get("tokens", {})
            return sess if sess._correlation_id else None
        except Exception:
            return None

    def register(self) -> str:
        """
        Register a new interactsh session.
        Returns the interaction hostname (e.g. abc123.oast.pro).
        """
        secret = str(uuid.uuid4()).replace("-", "")
        self._secret = secret

        try:
            resp = requests.post(
                f"{self._server}/register",
                json={"secret-key": secret, "correlation-id": ""},
                timeout=TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            raise InteractshError(f"Failed to register with {self._server}: {e}") from e

        self._correlation_id = data.get("correlation-id", "")
        self._host = data.get("host", "")
        if not self._host:
            raise InteractshError(f"No host returned from {self._server}: {data}")

        self._save_state()
        return self._host

    # ── token management ──────────────────────────────────────────────────

    def new_token(self, label: str = "") -> str:
        """
        Generate a unique per-test subdomain prefix.
        Returns the full canary URL: http://<token>.<host>/
        """
        token = hashlib.md5(f"{label}-{uuid.uuid4()}".encode()).hexdigest()[:12]
        self._tokens[token] = {
            "label":      label,
            "created_at": time.time(),
        }
        self._save_state()
        return token

    def url(self, token: str, scheme: str = "http", path: str = "/") -> str:
        """Build the OOB URL for a given token."""
        host = self._host or "oast.pro"
        return f"{scheme}://{token}.{host}{path}"

    def dns(self, token: str) -> str:
        """Build a DNS probe name for a given token."""
        host = self._host or "oast.pro"
        return f"{token}.{host}"

    # ── polling ───────────────────────────────────────────────────────────

    def poll(self, token: str = "") -> list[dict]:
        """
        Poll interactsh for interactions.
        If token is given, filter to just that prefix.
        Returns list of interaction dicts.
        """
        if not self._correlation_id:
            raise InteractshError("No active session. Run .register() first.")

        try:
            resp = requests.get(
                f"{self._server}/poll",
                params={
                    "id":     self._correlation_id,
                    "secret": self._secret,
                },
                timeout=TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            raise InteractshError(f"Poll failed: {e}") from e

        interactions = data.get("data", []) or []

        if token:
            interactions = [i for i in interactions
                            if token in i.get("unique-id", "")
                            or token in i.get("raw-request", "")]

        # Annotate with known labels
        for interaction in interactions:
            uid = interaction.get("unique-id", "")
            for tok, meta in self._tokens.items():
                if tok in uid:
                    interaction["_label"] = meta.get("label", "")
                    break

        return interactions

    def poll_all(self) -> list[dict]:
        return self.poll()

    @property
    def host(self) -> str:
        return self._host

    @property
    def active(self) -> bool:
        return bool(self._correlation_id and self._host)


# ── simple canary (no registration needed) ────────────────────────────────

class SimpleCanary:
    """
    Lightweight OOB canary using dnslog.cn or a static domain.
    No registration needed — just generate URLs and check manually.
    Useful when interactsh is blocked or for quick tests.
    """

    DNSLOG_DOMAIN = "dnslog.cn"

    def __init__(self, domain: str = ""):
        self._domain = domain or self.DNSLOG_DOMAIN

    def url(self, label: str = "", scheme: str = "http") -> str:
        slug = hashlib.md5(f"{label}-{time.time()}".encode()).hexdigest()[:10]
        return f"{scheme}://{slug}.{self._domain}/"

    def dns(self, label: str = "") -> str:
        slug = hashlib.md5(f"{label}-{time.time()}".encode()).hexdigest()[:10]
        return f"{slug}.{self._domain}"


# ── helpers for other modules ─────────────────────────────────────────────

def get_active_session() -> OOBSession | None:
    """
    Return the active OOB session if one exists, else None.
    Other modules call this to check if OOB is configured.
    """
    return OOBSession.load()


def quick_canary(label: str = "") -> tuple[str, str]:
    """
    Return (oob_url, oob_dns) for a quick test without session setup.
    Uses SimpleCanary — no polling, manual verification only.
    """
    c = SimpleCanary()
    return c.url(label), c.dns(label)


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Catch403 OOB Interaction Helper")
    parser.add_argument("--start",    action="store_true",
                        help="Register a new interactsh session")
    parser.add_argument("--poll",     action="store_true",
                        help="Poll for incoming interactions")
    parser.add_argument("--generate", action="store_true",
                        help="Generate a new per-test canary token")
    parser.add_argument("--token",    default="",
                        help="Token label for --generate")
    parser.add_argument("--filter",   default="",
                        help="Filter --poll results by token prefix")
    parser.add_argument("--server",   default=INTERACTSH_SERVER,
                        help=f"Interactsh server URL (default: {INTERACTSH_SERVER})")
    parser.add_argument("--status",   action="store_true",
                        help="Show current session status")
    parser.add_argument("--canary",   action="store_true",
                        help="Generate a quick canary URL (no session required)")
    args = parser.parse_args()

    if args.canary:
        url, dns = quick_canary(args.token or "test")
        print(f"{info} Quick canary (manual verification — check your DNS logs):")
        print(f"      URL: {url}")
        print(f"      DNS: {dns}")
        return

    if args.start:
        print(f"{run} Registering interactsh session with {args.server}...")
        sess = OOBSession(args.server)
        try:
            host = sess.register()
            print(f"{good} Session registered!")
            print(f"      OOB host: {bold}{host}{end}")
            print(f"      Session saved to: {_SESSION_FILE}")
            print(f"\n{info} Use this host as your OOB callback target:")
            print(f"      --oob {host}")
        except InteractshError as e:
            print(f"{bad} Registration failed: {e}")
        return

    if args.status:
        sess = OOBSession.load()
        if not sess:
            print(f"{info} No active session. Run --start to create one.")
        else:
            print(f"{good} Active session:")
            print(f"      Host:    {sess.host}")
            print(f"      Tokens:  {len(sess._tokens)}")
        return

    if args.generate:
        sess = OOBSession.load()
        if not sess:
            print(f"{bad} No session. Run --start first.")
            return
        token = sess.new_token(args.token or "test")
        print(f"{good} New canary token: {bold}{token}{end}")
        print(f"      HTTP URL: {sess.url(token)}")
        print(f"      DNS name: {sess.dns(token)}")
        return

    if args.poll:
        sess = OOBSession.load()
        if not sess:
            print(f"{bad} No session. Run --start first.")
            return
        print(f"{run} Polling {sess.host} for interactions...")
        try:
            hits = sess.poll(args.filter)
            if not hits:
                print(f"{info} No interactions yet.")
            else:
                print(f"{good} {len(hits)} interaction(s) received:\n")
                for h in hits:
                    protocol = h.get("protocol", "?").upper()
                    uid      = h.get("unique-id", "")
                    ts       = h.get("timestamp", "")
                    label    = h.get("_label", "")
                    print(f"  [{protocol}] {uid}  {ts}")
                    if label:
                        print(f"         Label: {label}")
                    if "remote-address" in h:
                        print(f"         From:  {h['remote-address']}")
                    print()
        except InteractshError as e:
            print(f"{bad} Poll error: {e}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
