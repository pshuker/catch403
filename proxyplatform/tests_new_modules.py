"""Tests for the second batch of new modules."""
import sys, os, tempfile, json, hashlib
sys.path.insert(0, os.path.dirname(__file__))

passed = failed = 0

def test(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  PASS  {name}")
        passed += 1
    except Exception as e:
        print(f"  FAIL  {name}: {e}")
        failed += 1

def assert_eq(a, b):
    assert a == b, f"{a!r} != {b!r}"

def assert_true(v):
    assert v, f"expected truthy, got {v!r}"

# ── helpers ────────────────────────────────────────────────────────────────

def _temp_scope():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        fname = f.name
    from modules.scope import Scope
    s = Scope(fname)
    return s, fname

def _test_scope_include():
    s, f = _temp_scope()
    s.add("target.com")
    assert s.is_in_scope("https://target.com/path"), "target.com should be in scope"
    assert not s.is_in_scope("https://other.com/"), "other.com should be out"
    os.unlink(f)

def _test_scope_exclude():
    s, f = _temp_scope()
    s.add("target.com")
    s.add("staging.target.com", "exclude")
    assert s.is_in_scope("https://target.com/api"), "base domain in"
    assert not s.is_in_scope("https://staging.target.com/"), "staging excluded"
    os.unlink(f)

def _test_scope_regex():
    s, f = _temp_scope()
    s.add(r".*\.target\.com")
    assert s.is_in_scope("https://api.target.com/v1")
    assert s.is_in_scope("https://sub.target.com/")
    assert not s.is_in_scope("https://evil.com/")
    os.unlink(f)

def _test_scope_list():
    s, f = _temp_scope()
    s.add("a.com")
    s.add("b.com", "exclude")
    rules = s.list_rules()
    assert len(rules) == 2
    assert rules[0]["type"] == "include"
    assert rules[1]["type"] == "exclude"
    os.unlink(f)

def _test_crack_md5():
    h = hashlib.md5(b"hello").hexdigest()
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
        f.write("wrong\nhello\nother\n"); fname = f.name
    try:
        from modules.hash_id import crack
        result = crack(h, fname)
        assert result is not None, "should crack"
        assert result["plain"] == "hello"
        assert result["type"] == "md5"
    finally:
        os.unlink(fname)

def _test_dns_save():
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html") as f:
        fname = f.name
    try:
        from modules.dns_rebinding import generate
        generate("test.com", "127.0.0.1", 80, fname)
        assert os.path.exists(fname), "file not saved"
        with open(fname) as f:
            content = f.read()
        assert "test.com" in content
    finally:
        if os.path.exists(fname): os.unlink(fname)

def _temp_log():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        fname = f.name
    os.unlink(fname)
    from modules.logger_plus import TrafficLog
    return TrafficLog(fname), fname

def _test_log_record():
    log, f = _temp_log()
    try:
        eid = log.record("GET", "https://target.com/path",
                         {"Host":"target.com"}, "", 200,
                         {"Content-Type":"text/html"}, "<html>ok</html>")
        assert isinstance(eid, int)
        entry = log.get(eid)
        assert entry is not None
        assert entry["method"] == "GET"
        assert entry["host"] == "target.com"
        assert entry["status"] == 200
    finally:
        os.unlink(f)

def _test_log_query():
    log, f = _temp_log()
    try:
        log.record("GET",  "https://target.com/",   {"Host":"target.com"}, "", 200, {}, "")
        log.record("POST", "https://other.com/api", {"Host":"other.com"},  "", 200, {}, "")
        results = log.query(host="target.com")
        assert len(results) == 1
        assert results[0]["host"] == "target.com"
    finally:
        os.unlink(f)

def _test_log_export():
    log, f = _temp_log()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out:
        outname = out.name
    try:
        log.record("GET", "https://target.com/", {}, "", 200, {}, "body")
        n = log.export_json(outname)
        assert n == 1
        with open(outname) as jf:
            data = json.load(jf)
        assert len(data) == 1
    finally:
        os.unlink(f)
        if os.path.exists(outname): os.unlink(outname)

def _test_log_clear():
    log, f = _temp_log()
    try:
        log.record("GET", "https://x.com/", {}, "", 200, {}, "")
        assert log.count() == 1
        log.clear()
        assert log.count() == 0
    finally:
        os.unlink(f)

def _test_cd_paths():
    from modules.content_discovery import ContentDiscovery
    cd = ContentDiscovery("https://t.com", ["admin"], extensions=["php","bak"])
    paths = cd._build_paths("https://t.com", "admin")
    assert "https://t.com/admin" in paths
    assert "https://t.com/admin.php" in paths
    assert "https://t.com/admin.bak" in paths

def _test_gql_schema():
    from modules.graphql_raider import parse_schema
    schema = {
        "queryType":    {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query",    "fields": [{"name": "user"}, {"name": "posts"}],
             "inputFields": [], "enumValues": []},
            {"name": "Mutation", "fields": [{"name": "createUser"}],
             "inputFields": [], "enumValues": []},
            {"name": "__Schema", "fields": [], "inputFields": [], "enumValues": []},
        ]
    }
    result = parse_schema(schema)
    assert "user"       in result["queries"]
    assert "posts"      in result["queries"]
    assert "createUser" in result["mutations"]
    assert "__Schema"   not in result["types"]

def _test_ti_url():
    from modules.turbo_intruder import Engine
    e = Engine("https://t.com/search?q=%s", threads=1)
    url, body = e._build_request("hello world")
    assert "hello%20world" in url or "hello+world" in url or "hello" in url, f"url={url}"

def _test_ti_body():
    from modules.turbo_intruder import Engine
    e = Engine("https://t.com/login", method="POST",
               body_template="user=admin&pass=%s", threads=1)
    url, body = e._build_request("secret")
    assert body == "user=admin&pass=secret", f"body={body}"

def _test_ti_filter():
    from modules.turbo_intruder import _default_filter, Result
    fn = _default_filter(baseline_length=500, threshold=50)
    boring      = Result("u","GET","p", 200, 510, 100)
    interesting = Result("u","GET","p", 200, 600, 100)
    error_res   = Result("u","GET","p", 500, 200, 100)
    assert not fn(boring)
    assert fn(interesting)
    assert fn(error_res)

def _test_rule_match():
    from modules.auto_repeater import Rule
    r = Rule(name="test", match_host="target.com")
    assert r.matches("GET", "https://target.com/path", {}, "")

def _test_rule_nomatch():
    from modules.auto_repeater import Rule
    r = Rule(name="test", match_host="target.com")
    assert not r.matches("GET", "https://other.com/path", {}, "")

def _test_rule_apply_remove():
    from modules.auto_repeater import Rule
    r = Rule(name="test", remove_headers=["Authorization"])
    h = {"Authorization": "Bearer xyz", "Content-Type": "application/json"}
    mod_h, body, url = r.apply(h, None, "https://t.com/")
    assert "Authorization" not in mod_h
    assert "Content-Type" in mod_h

def _test_rule_apply_add():
    from modules.auto_repeater import Rule
    r = Rule(name="test", add_headers={"X-Custom": "injected"})
    h = {"Host": "t.com"}
    mod_h, _, _ = r.apply(h, None, "https://t.com/")
    assert mod_h["X-Custom"] == "injected"
    assert mod_h["Host"] == "t.com"

def _test_rule_serial():
    from modules.auto_repeater import Rule
    r  = Rule(name="myRule", match_host="t.com", remove_headers=["Cookie"])
    r2 = Rule.from_dict(r.to_dict())
    assert r2.name == "myRule"
    assert r2.match_host == "t.com"
    assert "Cookie" in r2.remove_headers

# ── tests ──────────────────────────────────────────────────────────────────

print("\nnew-batch module tests\n")

from modules.scope import Scope
test("scope empty = everything in scope", lambda: (
    assert_true(_temp_scope()[0].is_in_scope("https://anything.com"))))
test("scope include rule restricts",      _test_scope_include)
test("scope exclude rule removes",        _test_scope_exclude)
test("scope regex rule works",            _test_scope_regex)
test("scope list_rules returns added",    _test_scope_list)

from modules.hash_id import identify, crack, HASH_PATTERNS
test("hash_id identifies MD5", lambda: (
    assert_true(any(r["name"] == "MD5" for r in identify("5d41402abc4b2a76b9719d911017c592")))))
test("hash_id identifies SHA-256", lambda: (
    assert_true(any(r["name"] == "SHA-256" for r in
        identify("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")))))
test("hash_id identifies SHA-1", lambda: (
    assert_true(any(r["name"] == "SHA-1" for r in
        identify("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")))))
test("hash_id identifies bcrypt", lambda: (
    assert_true(any(r["name"] == "bcrypt" for r in
        identify("$2b$12$KIXVoqLZSHlbovHg1g3H2.iKijMuT4SYPK3DPBR.VFEKAlPJVqhDK")))))
test("hash_id identifies JWT", lambda: (
    assert_true(any("JWT" in r["name"] for r in
        identify("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc123")))))
test("hash_id unknown returns empty",     lambda: assert_eq(identify("not_a_hash"), []))
test("hash_id crack md5 hello",           _test_crack_md5)
test("hash_id HASH_PATTERNS >= 20",       lambda: assert_true(len(HASH_PATTERNS) >= 20))

from modules.dns_rebinding import generate, attack_page_html, dns_record_suggestions, scanner_payloads
test("dns_rebinding generate returns dict", lambda: (
    assert_true(isinstance(generate("attacker.com", "127.0.0.1", 8080), dict))))
test("dns_rebinding attack page has domain", lambda: (
    assert_true("attacker.com" in attack_page_html("attacker.com", "127.0.0.1", 8080))))
test("dns_rebinding attack page has fetch", lambda: (
    assert_true("fetch" in attack_page_html("attacker.com", "127.0.0.1", 8080))))
test("dns_rebinding dns records non-empty", lambda: (
    assert_true(len(dns_record_suggestions("attacker.com", "127.0.0.1")) > 0)))
test("dns_rebinding scanner has 169.254", lambda: (
    assert_true(any(p["target_ip"] == "169.254.169.254"
                    for p in scanner_payloads("attacker.com")))))
test("dns_rebinding saves html file",      _test_dns_save)

from modules.response_beautifier import beautify, beautify_html, detect_format
test("beautifier detects json",  lambda: assert_eq(detect_format('{"k":"v"}', "application/json"), "json"))
test("beautifier detects html",  lambda: assert_eq(detect_format("<!DOCTYPE html>", "text/html"), "html"))
test("beautifier detects xml",   lambda: assert_eq(detect_format("<?xml version='1.0'?>", "text/xml"), "xml"))
test("beautifier formats json",  lambda: assert_true("  " in beautify('{"a":1,"b":2}', "application/json")))
test("beautifier html wraps pre",lambda: assert_true("<pre" in beautify_html('{"x":1}', "application/json")))
test("beautifier invalid json",  lambda: assert_eq(beautify("not json", "application/json"), "not json"))

from modules.logger_plus import TrafficLog
test("logger record and get",    _test_log_record)
test("logger query by host",     _test_log_query)
test("logger export json",       _test_log_export)
test("logger count returns int", lambda: assert_true(isinstance(_temp_log()[0].count(), int)))
test("logger clear empties db",  _test_log_clear)

from modules.content_discovery import ContentDiscovery, BUILTIN_WORDLIST, _normalize
test("content_discovery wordlist >= 50", lambda: assert_true(len(BUILTIN_WORDLIST) >= 50))
test("content_discovery normalize http",  lambda: assert_eq(_normalize("target.com"), "https://target.com"))
test("content_discovery strip slash",     lambda: assert_eq(_normalize("https://t.com/"), "https://t.com"))
test("content_discovery builds paths",   _test_cd_paths)

from modules.graphql_raider import parse_schema, INTROSPECTION_QUERY, INJECTION_PAYLOADS
test("graphql_raider has __schema",       lambda: assert_true("__schema" in INTROSPECTION_QUERY))
test("graphql_raider injection >= 5",     lambda: assert_true(len(INJECTION_PAYLOADS) >= 5))
test("graphql_raider parse_schema",      _test_gql_schema)
test("graphql_raider parse empty",        lambda: assert_eq(
    parse_schema(None), {"queries":[],"mutations":[],"types":{}}))

from modules.oauth_tester import check_well_known
test("oauth flags implicit flow", lambda: assert_true(any(
    "Implicit" in f["name"]
    for f in check_well_known({"response_types_supported": ["code","token"]}))))
test("oauth flags missing pkce", lambda: assert_true(any(
    "PKCE" in f["name"]
    for f in check_well_known({"response_types_supported": ["code"]}))))
test("oauth flags auth=none", lambda: assert_true(any(
    "public clients" in f["name"] or "none" in f["detail"].lower()
    for f in check_well_known({"token_endpoint_auth_methods_supported": ["client_secret_basic","none"]}))))
test("oauth empty config = no findings", lambda: assert_eq(check_well_known({}), []))

from modules.turbo_intruder import Engine, MARKER, _default_filter, _status_col
test("turbo MARKER is %s",         lambda: assert_eq(MARKER, "%s"))
test("turbo status colour 200",    lambda: assert_true("\033[" in _status_col(200)))
test("turbo url with payload",     _test_ti_url)
test("turbo body with payload",    _test_ti_body)
test("turbo default filter",       _test_ti_filter)

from modules.auto_repeater import Rule, AutoRepeater, PRESET_RULES
test("repeater rule matches host",      _test_rule_match)
test("repeater rule no-match host",     _test_rule_nomatch)
test("repeater rule remove header",     _test_rule_apply_remove)
test("repeater rule add header",        _test_rule_apply_add)
test("repeater rule serialise",         _test_rule_serial)
test("repeater preset rules >= 4",      lambda: assert_true(len(PRESET_RULES) >= 4))

from modules.intercepting_proxy import CA_DIR, CA_CRT, CA_KEY, _cert_cache
test("proxy CA paths defined",          lambda: assert_true(CA_DIR.endswith(".proxyplatform/ca")))
test("proxy cert_cache is dict",        lambda: assert_true(isinstance(_cert_cache, dict)))

# ── sqlmap_scanner ─────────────────────────────────────────────────────────

from modules.sqlmap_scanner import _parse_log, _sqlmap_bin

def _test_sqlmap_injectable():
    log = "[INFO] GET parameter 'id' appears to be 'MySQL >= 5.0 AND error-based' injectable"
    findings = _parse_log(log)
    inj = [f for f in findings if f["severity"] == "critical"]
    assert_true(len(inj) == 1)
    assert_true("id" in inj[0]["name"])

def _test_sqlmap_not_injectable():
    log = "[CRITICAL] all tested parameters do not appear to be injectable"
    findings = _parse_log(log)
    assert_true(any(f["name"] == "Not injectable" for f in findings))

def _test_sqlmap_dbms():
    log = "[INFO] the back-end DBMS is PostgreSQL"
    findings = _parse_log(log)
    dbms = next((f for f in findings if f["name"] == "DBMS Fingerprint"), None)
    assert_true(dbms is not None)
    assert_true("PostgreSQL" in dbms["detail"])

def _test_sqlmap_os():
    log = "[INFO] the remote operating system is 'Windows Server 2019'"
    findings = _parse_log(log)
    osf = next((f for f in findings if f["name"] == "Remote OS"), None)
    assert_true(osf is not None)
    assert_true("Windows" in osf["detail"])

def _test_sqlmap_payloads():
    log = (
        "[INFO] GET parameter 'q' appears to be 'boolean-based blind' injectable\n"
        "Payload: 1 AND 1=1\n"
        "Payload: 1 AND 1=2\n"
    )
    findings = _parse_log(log)
    inj = next((f for f in findings if f["severity"] == "critical"), None)
    assert_true(inj is not None)
    assert_true(len(inj.get("payloads", [])) >= 2)

def _test_sqlmap_bin():
    cmd, label = _sqlmap_bin()
    assert_true(isinstance(cmd, list))
    assert_true("sqlmap" in " ".join(cmd))
    assert_true(isinstance(label, str) and len(label) > 0)

def _test_sqlmap_post_param():
    log = "[INFO] POST parameter 'username' appears to be 'time-based blind' injectable"
    findings = _parse_log(log)
    inj = [f for f in findings if f["severity"] == "critical"]
    assert_true(len(inj) == 1)
    assert_true("username" in inj[0]["name"])

# ── commix_scanner ────────────────────────────────────────────────────────

from modules.commix_scanner import _parse_output, _commix_bin

def _test_commix_injectable():
    log = "[+] Parameter 'cmd' appears to be injectable via classic command injection"
    f = _parse_output(log)
    inj = [x for x in f if x["severity"] == "critical"]
    assert_true(len(inj) == 1)
    assert_true("cmd" in inj[0]["name"])

def _test_commix_not_injectable():
    log = "All tested HTTP headers appear to be not injectable."
    f = _parse_output(log)
    assert_true(any(x["name"] == "Not injectable" for x in f))

def _test_commix_os_shell():
    log = "[+] OS shell obtained via eval-based command injection"
    f = _parse_output(log)
    assert_true(any("OS Shell" in x["name"] for x in f))

def _test_commix_payloads():
    log = "[+] Parameter 'id' appears to be injectable via time-based command injection\n[payload] ;sleep 5;"
    f = _parse_output(log)
    inj = next((x for x in f if x["severity"] == "critical"), None)
    assert_true(inj is not None)
    assert_true(len(inj.get("payloads", [])) >= 1)

def _test_commix_bin():
    cmd, label = _commix_bin()
    assert_true(isinstance(cmd, list))
    assert_true("commix" in " ".join(cmd))
    assert_true(len(label) > 0)

test("commix parse injectable param",     _test_commix_injectable)
test("commix parse not injectable",       _test_commix_not_injectable)
test("commix parse OS shell obtained",    _test_commix_os_shell)
test("commix payloads attached",          _test_commix_payloads)
test("commix bin resolves to vendor",     _test_commix_bin)

# ── wapiti_scanner ────────────────────────────────────────────────────────

from modules.wapiti_scanner import _parse_report, _wapiti_bin, _SEV_ORDER

def _test_wapiti_parse_vuln():
    report = {
        "vulnerabilities": {
            "sql": [{"level": 3, "info": "SQLi in param id", "path": "/page?id=1",
                     "parameter": "id", "method": "GET", "http_request": "", "curl_command": ""}]
        },
        "anomalies": {},
        "infos": {},
    }
    findings = _parse_report(report)
    assert_true(len(findings) == 1)
    assert_eq(findings[0]["severity"], "high")
    assert_true("SQL" in findings[0]["name"])

def _test_wapiti_parse_anomaly():
    report = {
        "vulnerabilities": {},
        "anomalies": {
            "xss": [{"info": "Reflected anomaly", "path": "/search?q=test"}]
        },
        "infos": {},
    }
    findings = _parse_report(report)
    assert_true(any("Anomaly" in f["name"] for f in findings))

def _test_wapiti_sev_order():
    assert_true(_SEV_ORDER["critical"] < _SEV_ORDER["high"] < _SEV_ORDER["info"])

def _test_wapiti_empty_report():
    findings = _parse_report({"vulnerabilities": {}, "anomalies": {}, "infos": {}})
    assert_eq(findings, [])

def _test_wapiti_bin():
    cmd, label = _wapiti_bin()
    assert_true(isinstance(cmd, list))
    assert_true("wapiti" in " ".join(cmd))

test("wapiti parse vulnerability finding",   _test_wapiti_parse_vuln)
test("wapiti parse anomaly finding",         _test_wapiti_parse_anomaly)
test("wapiti severity order correct",        _test_wapiti_sev_order)
test("wapiti empty report = no findings",    _test_wapiti_empty_report)
test("wapiti bin found in venv",             _test_wapiti_bin)

# ── nosql_scanner ─────────────────────────────────────────────────────────

from modules.nosql_scanner import (
    AUTH_BYPASS_JSON, MONGO_OPERATOR_PAYLOADS, BLIND_TRUE, BLIND_FALSE,
    _is_json_endpoint, _looks_like_success,
)

def _test_nosql_payloads_populated():
    assert_true(len(AUTH_BYPASS_JSON) >= 4)
    assert_true(len(MONGO_OPERATOR_PAYLOADS) >= 5)
    assert_true(len(BLIND_TRUE) == len(BLIND_FALSE))

def _test_nosql_looks_like_success_status():
    class _R:
        def __init__(self, status, text): self.status_code = status; self.text = text
    assert_true(_looks_like_success(_R(200, "ok"), 403, 100))
    assert_true(not _looks_like_success(_R(403, "x" * 100), 403, 100))

def _test_nosql_looks_like_success_body():
    class _R:
        def __init__(self, status, text): self.status_code = status; self.text = text
    # Same status but body grew >30% = suspicious
    assert_true(_looks_like_success(_R(200, "x" * 200), 200, 100))

def _test_nosql_ne_payload():
    ne = next((p for p in MONGO_OPERATOR_PAYLOADS if "$ne" in p), None)
    assert_true(ne is not None)

def _test_nosql_gt_payload():
    gt = next((p for p in MONGO_OPERATOR_PAYLOADS if "$gt" in p), None)
    assert_true(gt is not None)

test("nosql payload banks populated",        _test_nosql_payloads_populated)
test("nosql success detection by status",    _test_nosql_looks_like_success_status)
test("nosql success detection by body diff", _test_nosql_looks_like_success_body)
test("nosql $ne operator in payloads",       _test_nosql_ne_payload)
test("nosql $gt operator in payloads",       _test_nosql_gt_payload)

# ── sqlmap_scanner ─────────────────────────────────────────────────────────

from modules.sqlmap_scanner import _parse_log, _sqlmap_bin

test("sqlmap parse injectable param",    _test_sqlmap_injectable)
test("sqlmap parse not injectable",      _test_sqlmap_not_injectable)
test("sqlmap parse dbms fingerprint",    _test_sqlmap_dbms)
test("sqlmap parse remote OS",           _test_sqlmap_os)
test("sqlmap payloads attached",         _test_sqlmap_payloads)
test("sqlmap bin found in venv",         _test_sqlmap_bin)
test("sqlmap parse POST param",          _test_sqlmap_post_param)

# ── summary ────────────────────────────────────────────────────────────────
print(f"\n{passed} passed, {failed} failed\n")
if failed:
    sys.exit(1)
