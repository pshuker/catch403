#!/usr/bin/python3
"""
Response Beautifier — pretty-print HTTP response bodies (JSON, HTML, XML, JS).

Adds syntax highlighting via ANSI codes in terminal, and returns
formatted HTML for the web UI.

Usage:
  from modules.response_beautifier import beautify, beautify_html
  text = beautify(content, content_type)   # terminal (ANSI)
  html = beautify_html(content, content_type)  # web UI
"""
import json
import re

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False

try:
    from lxml import etree
    _HAS_LXML = True
except ImportError:
    _HAS_LXML = False

from core.colors import bold, end, green, yellow, red


# ── detect format ──────────────────────────────────────────────────────────

def _detect(content: str, content_type: str) -> str:
    ct = content_type.lower()
    if "json" in ct or content.lstrip().startswith(("{", "[")):
        return "json"
    if "xml" in ct or content.lstrip().startswith("<?xml") or "<soap" in content[:200].lower():
        return "xml"
    if "html" in ct or content.lstrip().lower().startswith(("<!doctype", "<html")):
        return "html"
    if "javascript" in ct or "js" in ct:
        return "js"
    return "text"


# ── JSON ───────────────────────────────────────────────────────────────────

def _format_json(content: str) -> str:
    try:
        obj = json.loads(content)
        return json.dumps(obj, indent=2, ensure_ascii=False)
    except json.JSONDecodeError:
        return content


def _highlight_json_ansi(text: str) -> str:
    def repl(m):
        s = m.group(0)
        if s.startswith('"') and s.endswith('":'):
            return f"\033[36m{s}\033[0m"       # key: cyan
        if s.startswith('"'):
            return f"\033[92m{s}\033[0m"        # string: green
        if s in ("true", "false"):
            return f"\033[93m{s}\033[0m"        # bool: yellow
        if s == "null":
            return f"\033[91m{s}\033[0m"        # null: red
        if re.match(r'^-?\d', s):
            return f"\033[94m{s}\033[0m"        # number: blue
        return s

    return re.sub(
        r'"[^"\\]*(?:\\.[^"\\]*)*"(?=\s*:)|"[^"\\]*(?:\\.[^"\\]*)*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null',
        repl, text
    )


def _highlight_json_html(text: str) -> str:
    def repl(m):
        s = m.group(0).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        if s.endswith('":'[1:]) or (s.startswith('"') and m.group(0).endswith(":")):
            return f'<span class="jk">{s}</span>'
        if s.startswith('"'):
            return f'<span class="js">{s}</span>'
        if s in ("true", "false"):
            return f'<span class="jb">{s}</span>'
        if s == "null":
            return f'<span class="jn">{s}</span>'
        if re.match(r'^-?\d', s):
            return f'<span class="jnum">{s}</span>'
        return s

    escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(
        r'"[^"\\]*(?:\\.[^"\\]*)*"\s*:?|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null',
        repl, escaped
    )


# ── HTML ───────────────────────────────────────────────────────────────────

def _format_html(content: str) -> str:
    if _HAS_BS4:
        try:
            return BeautifulSoup(content, "html.parser").prettify()
        except Exception:
            pass
    # minimal indent fallback
    indent = 0
    lines = []
    for line in re.split(r"(<[^>]+>)", content):
        line = line.strip()
        if not line:
            continue
        if re.match(r"</\w", line):
            indent = max(0, indent - 2)
        lines.append(" " * indent + line)
        if re.match(r"<\w[^/]*[^/]>$", line) and not re.match(r"<(br|hr|img|input|meta|link)", line, re.I):
            indent += 2
    return "\n".join(lines)


# ── XML ────────────────────────────────────────────────────────────────────

def _format_xml(content: str) -> str:
    if _HAS_LXML:
        try:
            root = etree.fromstring(content.encode())
            return etree.tostring(root, pretty_print=True, encoding="unicode")
        except Exception:
            pass
    return content


# ── public API ─────────────────────────────────────────────────────────────

def beautify(content: str, content_type: str = "") -> str:
    """Return ANSI-highlighted string for terminal output."""
    fmt = _detect(content, content_type)
    if fmt == "json":
        formatted = _format_json(content)
        return _highlight_json_ansi(formatted)
    if fmt == "html":
        return _format_html(content)
    if fmt == "xml":
        return _format_xml(content)
    return content


def beautify_html(content: str, content_type: str = "") -> str:
    """Return syntax-highlighted HTML fragment for the web UI."""
    fmt = _detect(content, content_type)
    escaped = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    css = """<style>
.jk   { color: #9cdcfe; }
.js   { color: #ce9178; }
.jb   { color: #569cd6; }
.jn   { color: #569cd6; }
.jnum { color: #b5cea8; }
pre.bf{ font-family: monospace; font-size: 12px; line-height: 1.4;
        background: #1e1e1e; color: #d4d4d4; padding: 12px;
        overflow: auto; border-radius: 4px; }
</style>"""

    if fmt == "json":
        formatted = _format_json(content)
        highlighted = _highlight_json_html(formatted)
        return f'{css}<pre class="bf">{highlighted}</pre>'

    if fmt == "html":
        formatted = _format_html(content)
        formatted_esc = formatted.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return f'{css}<pre class="bf">{formatted_esc}</pre>'

    if fmt == "xml":
        formatted = _format_xml(content)
        formatted_esc = formatted.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return f'{css}<pre class="bf">{formatted_esc}</pre>'

    return f'{css}<pre class="bf">{escaped}</pre>'


def detect_format(content: str, content_type: str = "") -> str:
    return _detect(content, content_type)


def main():
    import sys
    import argparse
    parser = argparse.ArgumentParser(description="Pretty-print HTTP response bodies")
    parser.add_argument("file", nargs="?", help="File to beautify (default: stdin)")
    parser.add_argument("--ct", dest="content_type", default="",
                        help="Content-Type hint (e.g. application/json)")
    parser.add_argument("--html-out", action="store_true",
                        help="Output HTML fragment instead of ANSI terminal")
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            content = f.read()
    else:
        content = sys.stdin.read()

    if args.html_out:
        print(beautify_html(content, args.content_type))
    else:
        print(beautify(content, args.content_type))


if __name__ == "__main__":
    main()
