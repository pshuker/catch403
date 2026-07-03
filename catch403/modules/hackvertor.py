#!/usr/bin/python3
"""
Hackvertor — chainable tag-based encoding/transformation engine.

Apply transformations using tags: <@tag>input<@/tag>
Tags can be nested and chained. Output of inner tag is input to outer tag.

Supported tags:
  Encoding : url_encode, url_decode, b64_encode, b64_decode,
             html_encode, html_decode, hex_encode, hex_decode,
             unicode_escape, rot13
  Mutation : upper, lower, reverse, repeat(N), pad_left(N,char)
  Hashing  : md5, sha1, sha256
  Inspect  : length, bytecount

Usage:
  ../.venv/bin/python3 modules/hackvertor.py '<@url_encode><@b64_encode>hello world<@/b64_encode><@/url_encode>'
  ../.venv/bin/python3 modules/hackvertor.py --list       (show all tags)
  echo "hello" | ../.venv/bin/python3 modules/hackvertor.py --stdin --tag url_encode
"""
import argparse
import base64
import hashlib
import html as _html
import re
import sys
import urllib.parse

from core.colors import bold, underline, end, green, info, tab


# ── transform registry ─────────────────────────────────────────────────────

def _url_encode(s, *_):    return urllib.parse.quote(s, safe="")
def _url_decode(s, *_):    return urllib.parse.unquote(s)
def _b64_encode(s, *_):    return base64.b64encode(s.encode()).decode()
def _b64_decode(s, *_):    return base64.b64decode(s + "==").decode(errors="replace")
def _html_encode(s, *_):   return _html.escape(s)
def _html_decode(s, *_):   return _html.unescape(s)
def _hex_encode(s, *_):    return s.encode().hex()
def _hex_decode(s, *_):    return bytes.fromhex(s).decode(errors="replace")
def _rot13(s, *_):         return s.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                                             "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
def _unicode_escape(s, *_):return s.encode("unicode_escape").decode()
def _upper(s, *_):         return s.upper()
def _lower(s, *_):         return s.lower()
def _reverse(s, *_):       return s[::-1]
def _length(s, *_):        return str(len(s))
def _bytecount(s, *_):     return str(len(s.encode()))
def _md5(s, *_):           return hashlib.md5(s.encode()).hexdigest()
def _sha1(s, *_):          return hashlib.sha1(s.encode()).hexdigest()
def _sha256(s, *_):        return hashlib.sha256(s.encode()).hexdigest()
def _repeat(s, args):
    n = int(args[0]) if args else 2
    return s * n
def _pad_left(s, args):
    width = int(args[0]) if args else 10
    char  = args[1] if len(args) > 1 else "0"
    return s.rjust(width, char)
def _raw(s, *_): return s

TAGS: dict[str, tuple[callable, str]] = {
    "url_encode":     (_url_encode,    "URL-encode (percent encoding)"),
    "url_decode":     (_url_decode,    "URL-decode"),
    "b64_encode":     (_b64_encode,    "Base64 encode"),
    "b64_decode":     (_b64_decode,    "Base64 decode"),
    "html_encode":    (_html_encode,   "HTML entity encode"),
    "html_decode":    (_html_decode,   "HTML entity decode"),
    "hex_encode":     (_hex_encode,    "Hex encode (UTF-8 bytes)"),
    "hex_decode":     (_hex_decode,    "Hex decode"),
    "rot13":          (_rot13,         "ROT13"),
    "unicode_escape": (_unicode_escape,"Python unicode escape (\\uXXXX)"),
    "upper":          (_upper,         "Uppercase"),
    "lower":          (_lower,         "Lowercase"),
    "reverse":        (_reverse,       "Reverse string"),
    "length":         (_length,        "Length of string"),
    "bytecount":      (_bytecount,     "UTF-8 byte count"),
    "md5":            (_md5,           "MD5 hex digest"),
    "sha1":           (_sha1,          "SHA-1 hex digest"),
    "sha256":         (_sha256,        "SHA-256 hex digest"),
    "repeat":         (_repeat,        "Repeat N times: <@repeat(3)>x<@/repeat>"),
    "pad_left":       (_pad_left,      "Pad left: <@pad_left(8,0)>x<@/pad_left>"),
}


# ── parser ─────────────────────────────────────────────────────────────────

_TAG_OPEN  = re.compile(r"<@(\w+)(?:\(([^)]*)\))?>((?:(?!<@).)*?)<@/\1>", re.DOTALL)


def convert(text: str) -> str:
    """Recursively evaluate innermost <@tag>...</@tag> first (inside-out)."""
    prev = None
    while prev != text:
        prev = text
        text = _TAG_OPEN.sub(_apply_tag, text)
    return text


def _apply_tag(m: re.Match) -> str:
    tag_name = m.group(1)
    args_str = m.group(2) or ""
    content  = m.group(3)
    args     = [a.strip() for a in args_str.split(",") if a.strip()] if args_str else []
    fn, _    = TAGS.get(tag_name, (_raw, "unknown"))
    return fn(content, args)


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Hackvertor — chainable tag-based encoding")
    parser.add_argument("input",   nargs="?", help="Input string with <@tag>...</@tag> markup")
    parser.add_argument("--stdin", action="store_true", help="Read input from stdin")
    parser.add_argument("--tag",   dest="tag", help="Apply a single tag to stdin/input (no markup needed)")
    parser.add_argument("--list",  action="store_true", help="List all available tags")
    args = parser.parse_args()

    if args.list:
        print(f"\n{bold}{underline}Hackvertor tags{end}\n")
        for name, (_, desc) in TAGS.items():
            print(f"  {green}<@{name}>{end}  —  {desc}")
        print()
        return

    if args.stdin:
        text = sys.stdin.read().rstrip("\n")
    elif args.input:
        text = args.input
    else:
        parser.print_help()
        return

    if args.tag:
        fn, _ = TAGS.get(args.tag, (_raw, ""))
        print(fn(text, []))
    else:
        print(convert(text))


if __name__ == "__main__":
    main()
