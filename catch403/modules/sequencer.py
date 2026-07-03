#!/usr/bin/python3
"""
Sequencer — analyses randomness/entropy of session tokens.

Collects a sample of tokens (from a live endpoint or a file) and runs:
  - Shannon entropy (bits per character)
  - Bit-level frequency analysis (detects bias toward 0 or 1)
  - FIPS 140-2 monobit test
  - Compression ratio test (high compressibility = low randomness)
  - Verdict: STRONG / MODERATE / WEAK

Usage:
  # Collect 200 tokens from a live endpoint (authorised targets only):
  ../.venv/bin/python3 modules/sequencer.py -u https://target/login \
      --param session --method GET -n 200

  # Analyse tokens from a file (one per line):
  ../.venv/bin/python3 modules/sequencer.py -f tokens.txt
"""
import argparse
import math
import statistics
import zlib
from collections import Counter

import requests

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab


# ── entropy ────────────────────────────────────────────────────────────────

def shannon_entropy(token: str) -> float:
    if not token:
        return 0.0
    counts = Counter(token)
    length = len(token)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def bit_entropy(tokens: list[str]) -> float:
    bits = "".join(format(ord(c), "08b") for t in tokens for c in t)
    if not bits:
        return 0.0
    ones = bits.count("1")
    p = ones / len(bits)
    if p in (0, 1):
        return 0.0
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


def compression_ratio(tokens: list[str]) -> float:
    joined = "\n".join(tokens).encode()
    compressed = zlib.compress(joined, level=9)
    return len(compressed) / len(joined) if joined else 1.0


def monobit_test(tokens: list[str]) -> tuple[bool, float]:
    bits = "".join(format(ord(c), "08b") for t in tokens for c in t)
    n = len(bits)
    if n == 0:
        return False, 0.0
    ones = bits.count("1")
    s = abs(ones - (n - ones)) / math.sqrt(n)
    return s < 1.96, s   # passes if s < 1.96 (≈95% confidence)


# ── collection ─────────────────────────────────────────────────────────────

def collect_from_url(url: str, param: str, method: str, count: int,
                     headers: dict | None = None) -> list[str]:
    tokens: list[str] = []
    h = headers or {}
    print(f"{run} Collecting {count} tokens from {bold}{url}{end} ...")
    for i in range(count):
        try:
            r = (requests.post if method.upper() == "POST" else requests.get)(
                url, headers=h, timeout=10)
            if param:
                for cookie_name, cookie_val in r.cookies.items():
                    if param.lower() in cookie_name.lower():
                        tokens.append(cookie_val)
                        break
                else:
                    val = r.headers.get(param) or r.json().get(param, "") if \
                        "json" in r.headers.get("Content-Type", "") else ""
                    if val:
                        tokens.append(str(val))
            else:
                for _, v in r.cookies.items():
                    tokens.append(v)
                    break
        except Exception as e:
            print(f"{tab}{bad} Request {i+1} failed: {e}")
        if (i + 1) % 25 == 0:
            print(f"{tab}{info} Collected {i+1}/{count}")
    return tokens


# ── analysis ───────────────────────────────────────────────────────────────

def analyse(tokens: list[str]) -> dict:
    if not tokens:
        print(f"{bad} No tokens to analyse.")
        return {}

    entropies = [shannon_entropy(t) for t in tokens]
    avg_entropy = statistics.mean(entropies)
    token_lengths = [len(t) for t in tokens]
    bit_ent = bit_entropy(tokens)
    comp = compression_ratio(tokens)
    monobit_pass, monobit_s = monobit_test(tokens)
    unique_ratio = len(set(tokens)) / len(tokens)

    print(f"\n{bold}{underline}Sequencer Results ({len(tokens)} tokens){end}")
    print(f"{tab}Token lengths     : min={min(token_lengths)}  max={max(token_lengths)}  avg={statistics.mean(token_lengths):.1f}")
    print(f"{tab}Avg char entropy  : {avg_entropy:.4f} bits/char")
    print(f"{tab}Bit-level entropy : {bit_ent:.4f} bits  (ideal=1.0)")
    print(f"{tab}Compression ratio : {comp:.3f}  (ideal≈1.0, low=predictable)")
    print(f"{tab}Monobit test      : {'PASS' if monobit_pass else 'FAIL'}  (s={monobit_s:.3f})")
    print(f"{tab}Uniqueness        : {unique_ratio:.1%}  ({len(set(tokens))}/{len(tokens)} unique)")

    # verdict
    score = sum([
        avg_entropy >= 3.5,
        bit_ent >= 0.9,
        comp >= 0.85,
        monobit_pass,
        unique_ratio >= 0.99,
    ])
    if score >= 4:
        verdict, colour = "STRONG",   green
    elif score >= 2:
        verdict, colour = "MODERATE", yellow
    else:
        verdict, colour = "WEAK",     red

    print(f"\n{tab}Verdict: {colour}{bold}{verdict}{end} ({score}/5 checks passed)\n")

    return {
        "count": len(tokens), "avg_entropy": avg_entropy,
        "bit_entropy": bit_ent, "compression_ratio": comp,
        "monobit_pass": monobit_pass, "unique_ratio": unique_ratio,
        "verdict": verdict,
    }


def main():
    parser = argparse.ArgumentParser(description="Analyse session token randomness")
    parser.add_argument("-u",       dest="url",    help="Live endpoint URL to collect tokens from")
    parser.add_argument("-f",       dest="file",   help="File of tokens (one per line)")
    parser.add_argument("--param",  dest="param",  default="", help="Cookie/header/JSON key to extract")
    parser.add_argument("--method", dest="method", default="GET", help="HTTP method (default: GET)")
    parser.add_argument("-n",       dest="count",  type=int, default=100, help="Number of tokens (default: 100)")
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            tokens = [line.strip() for line in f if line.strip()]
    elif args.url:
        tokens = collect_from_url(args.url, args.param, args.method, args.count)
    else:
        parser.error("Provide -u URL or -f token file.")

    analyse(tokens)


if __name__ == "__main__":
    main()
