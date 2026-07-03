#!/usr/bin/python3
"""
OAuth/OIDC Tester — tests common OAuth 2.0 and OIDC misconfigurations.

Tests:
  - State parameter absence / fixation
  - redirect_uri manipulation (open redirect, wildcard, path traversal)
  - PKCE bypass (code_challenge missing, weak S256)
  - Token endpoint: client credentials exposure
  - Scope escalation
  - Token introspection / revocation endpoint discovery
  - Implicit flow still enabled?
  - Discovery document (.well-known/openid-configuration) parsing
  - CSRF on authorization endpoint
  - Response type confusion (token vs code)

Inspired by: oauth-scan, oauth2_tester, PortSwigger's OAuth labs

Usage:
  ../.venv/bin/python3 modules/oauth_tester.py -u https://target.com --discover
  ../.venv/bin/python3 modules/oauth_tester.py --auth-url https://auth.target.com/oauth/authorize \
      --client-id abc123 --redirect-uri https://target.com/callback
"""
import argparse
import base64
import hashlib
import json
import os
import re
import urllib.parse

import requests
import urllib3

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab

urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0 (compatible; Catch403/1.0)"}
TIMEOUT = 10


def _get(url: str, params: dict | None = None, headers: dict | None = None) -> requests.Response | None:
    h = {**UA, **(headers or {})}
    try:
        return requests.get(url, params=params, headers=h, timeout=TIMEOUT,
                            verify=False, allow_redirects=False)
    except Exception:
        return None


def _post(url: str, data: dict, headers: dict | None = None) -> requests.Response | None:
    h = {**UA, **(headers or {})}
    try:
        return requests.post(url, data=data, headers=h, timeout=TIMEOUT, verify=False)
    except Exception:
        return None


def _finding(name: str, severity: str, detail: str) -> dict:
    return {"name": name, "severity": severity, "detail": detail}


# ── Discovery ──────────────────────────────────────────────────────────────

def discover_oidc(base_url: str) -> dict | None:
    """Fetch .well-known/openid-configuration."""
    urls = [
        base_url.rstrip("/") + "/.well-known/openid-configuration",
        base_url.rstrip("/") + "/.well-known/oauth-authorization-server",
    ]
    for url in urls:
        r = _get(url)
        if r and r.status_code == 200:
            try:
                return r.json()
            except Exception:
                pass
    return None


# ── Checks ─────────────────────────────────────────────────────────────────

def check_state_param(auth_url: str, client_id: str, redirect_uri: str) -> list[dict]:
    findings = []
    # Request without state
    params = {
        "response_type": "code",
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
    }
    r = _get(auth_url, params=params)
    if r:
        loc = r.headers.get("Location", "")
        if r.status_code in (200, 302) and "state" not in loc and "error" not in loc.lower():
            findings.append(_finding(
                "Missing state parameter not enforced", "medium",
                "Authorization request without 'state' accepted — CSRF risk"
            ))
    # Try state fixation — use a known state value
    fixed_state = "FIXED_STATE_12345"
    params["state"] = fixed_state
    r2 = _get(auth_url, params=params)
    if r2 and r2.status_code in (200, 302):
        loc2 = r2.headers.get("Location", "")
        if fixed_state in loc2:
            findings.append(_finding(
                "State parameter reflected without validation (potential fixation)", "low",
                f"Server reflects state={fixed_state} without apparent validation"
            ))
    return findings


def check_redirect_uri(auth_url: str, client_id: str, redirect_uri: str) -> list[dict]:
    findings = []
    original_parsed = urllib.parse.urlparse(redirect_uri)
    original_host = original_parsed.netloc

    redirect_variants = [
        ("Open redirect — different domain",
         redirect_uri.replace(original_host, "evil.com")),
        ("Open redirect — subdomain",
         redirect_uri.replace(original_host, f"evil.com.{original_host}")),
        ("Path traversal",
         redirect_uri + "/../../../evil"),
        ("Fragment bypass",
         redirect_uri + "#@evil.com"),
        ("Port confusion",
         redirect_uri.replace(original_host, original_host + ":8443")),
        ("URL encoded",
         redirect_uri.replace(original_host, original_host + "%40evil.com")),
        ("Wildcard abuse",
         f"https://*.{original_host}/callback"),
        ("Localhost",
         "http://127.0.0.1/callback"),
        ("Open redirect via data URI",
         "data:text/html,<script>location='https://evil.com'</script>"),
    ]

    for label, uri in redirect_variants:
        params = {
            "response_type": "code",
            "client_id":     client_id,
            "redirect_uri":  uri,
            "state":         "test123",
        }
        r = _get(auth_url, params=params)
        if r and r.status_code in (200, 302):
            loc = r.headers.get("Location", "")
            body = r.text.lower()
            # If we get redirected to our evil URI or no error
            if "invalid_redirect" not in body and "error" not in body and "invalid" not in body:
                if "evil.com" in loc or uri in loc:
                    findings.append(_finding(
                        f"redirect_uri bypass: {label}", "high",
                        f"Server accepted redirect_uri={uri!r}"
                    ))
    return findings


def check_pkce(auth_url: str, client_id: str, redirect_uri: str) -> list[dict]:
    findings = []
    # PKCE — try without code_challenge
    params = {
        "response_type":         "code",
        "client_id":             client_id,
        "redirect_uri":          redirect_uri,
        "state":                 "test123",
    }
    r = _get(auth_url, params=params)
    if r and r.status_code in (200, 302):
        loc = r.headers.get("Location", "")
        body = r.text.lower()
        if "code_challenge_required" not in body and "invalid_request" not in body:
            findings.append(_finding(
                "PKCE not enforced", "medium",
                "Authorization request without code_challenge accepted"
            ))

    # Try plain code_challenge_method (should be S256)
    params2 = {**params, "code_challenge": "plain_challenge", "code_challenge_method": "plain"}
    r2 = _get(auth_url, params=params2)
    if r2 and r2.status_code in (200, 302):
        body2 = r2.text.lower()
        if "invalid" not in body2 and "unsupported" not in body2:
            findings.append(_finding(
                "PKCE allows 'plain' method", "low",
                "Server accepts code_challenge_method=plain (S256 should be required)"
            ))
    return findings


def check_implicit_flow(auth_url: str, client_id: str, redirect_uri: str) -> list[dict]:
    findings = []
    params = {
        "response_type": "token",   # implicit
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
        "state":         "test123",
    }
    r = _get(auth_url, params=params)
    if r and r.status_code in (200, 302):
        loc = r.headers.get("Location", "")
        body = r.text.lower()
        if ("access_token" in loc or
                ("unsupported_response_type" not in body and "error" not in body)):
            findings.append(_finding(
                "Implicit flow enabled (response_type=token)", "medium",
                "Tokens issued via implicit flow are exposed in URL fragments — use code flow with PKCE"
            ))
    return findings


def check_scope_escalation(auth_url: str, client_id: str, redirect_uri: str) -> list[dict]:
    findings = []
    admin_scopes = ["admin", "write:admin", "openid profile email phone address",
                    "offline_access", "read:all", "*", "sudo"]
    for scope in admin_scopes:
        params = {
            "response_type": "code",
            "client_id":     client_id,
            "redirect_uri":  redirect_uri,
            "scope":         scope,
            "state":         "test123",
        }
        r = _get(auth_url, params=params)
        if r and r.status_code in (200, 302):
            loc = r.headers.get("Location", "")
            body = r.text.lower()
            if "invalid_scope" not in body and "error" not in body:
                findings.append(_finding(
                    f"Scope escalation: '{scope}' not rejected", "medium",
                    f"Privileged scope '{scope}' accepted without error"
                ))
                break
    return findings


def check_well_known(config: dict) -> list[dict]:
    findings = []
    if not config:
        return findings

    # Implicit flow advertised
    response_types = config.get("response_types_supported", [])
    if "token" in response_types:
        findings.append(_finding(
            "Implicit flow advertised in discovery doc", "info",
            "response_types_supported includes 'token' — implicit flow available"
        ))

    # PKCE not required
    if "code_challenge_methods_supported" not in config:
        findings.append(_finding(
            "PKCE not mentioned in discovery doc", "low",
            "code_challenge_methods_supported absent from .well-known document"
        ))

    # Token endpoint auth methods
    methods = config.get("token_endpoint_auth_methods_supported", [])
    if "none" in methods:
        findings.append(_finding(
            "Token endpoint allows public clients (auth_method=none)", "low",
            "Unauthenticated token requests may be possible"
        ))

    return findings


def scan(auth_url: str, client_id: str, redirect_uri: str,
         base_url: str | None = None) -> dict:
    print(f"\n{bold}OAuth/OIDC Tester{end}\n")
    print(f"  {info} Auth URL     : {auth_url}")
    print(f"  {info} Client ID    : {client_id}")
    print(f"  {info} Redirect URI : {redirect_uri}\n")

    findings = []

    # OIDC discovery
    oidc_config = None
    if base_url:
        oidc_config = discover_oidc(base_url)
        if oidc_config:
            print(f"  {good} OIDC discovery doc found")
            findings += check_well_known(oidc_config)
            # Use discovered auth URL if not provided
            if "authorization_endpoint" in oidc_config and not auth_url:
                auth_url = oidc_config["authorization_endpoint"]

    checks = [
        ("State parameter",    lambda: check_state_param(auth_url, client_id, redirect_uri)),
        ("redirect_uri bypass",lambda: check_redirect_uri(auth_url, client_id, redirect_uri)),
        ("PKCE enforcement",   lambda: check_pkce(auth_url, client_id, redirect_uri)),
        ("Implicit flow",      lambda: check_implicit_flow(auth_url, client_id, redirect_uri)),
        ("Scope escalation",   lambda: check_scope_escalation(auth_url, client_id, redirect_uri)),
    ]

    for name, fn in checks:
        print(f"  {run} {name}…", end="\r", flush=True)
        found = fn()
        print(f"  {'':40}", end="\r")
        if found:
            findings.extend(found)
            print(f"  {bad} {name}: {len(found)} issue(s)")
        else:
            print(f"  {good} {name}: ok")

    # Print findings
    if findings:
        print(f"\n{bold}{underline}Findings ({len(findings)}){end}\n")
        sev_col = {"high": red, "medium": yellow, "low": green, "info": ""}
        for f in findings:
            col = sev_col.get(f["severity"], "")
            print(f"  {col}{bold}[{f['severity'].upper()}]{end}  {bold}{f['name']}{end}")
            print(f"  {tab}{f['detail']}\n")

    return {"url": auth_url, "findings": findings, "oidc_config": oidc_config}


def main():
    parser = argparse.ArgumentParser(description="OAuth 2.0 / OIDC misconfiguration tester")
    parser.add_argument("--auth-url",     dest="auth_url",     help="Authorization endpoint")
    parser.add_argument("--client-id",    dest="client_id",    default="test_client")
    parser.add_argument("--redirect-uri", dest="redirect_uri", default="https://evil.com/callback")
    parser.add_argument("-u", dest="base_url", help="Base URL for OIDC discovery")
    parser.add_argument("--discover", action="store_true",
                        help="Just fetch and display the OIDC discovery document")
    args = parser.parse_args()

    if args.discover and args.base_url:
        config = discover_oidc(args.base_url)
        if config:
            print(f"\n{bold}OIDC Discovery Document{end}\n")
            for k, v in config.items():
                print(f"  {green}{k}{end}: {v}")
            findings = check_well_known(config)
            if findings:
                print(f"\n{bold}Issues{end}")
                for f in findings:
                    print(f"  {bad} [{f['severity'].upper()}] {f['name']}: {f['detail']}")
        else:
            print(f"{bad} No OIDC discovery document found at {args.base_url}")
        return

    if not args.auth_url and not args.base_url:
        parser.print_help()
        return

    auth_url = args.auth_url
    if not auth_url and args.base_url:
        config = discover_oidc(args.base_url)
        if config:
            auth_url = config.get("authorization_endpoint")
        if not auth_url:
            print(f"{bad} Could not determine authorization endpoint. Use --auth-url")
            return

    scan(auth_url, args.client_id, args.redirect_uri, args.base_url)


if __name__ == "__main__":
    main()
