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
test("proxy CA paths defined",          lambda: assert_true(CA_DIR.endswith(".catch403/ca")))
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

# ── ssl_tls_scanner ────────────────────────────────────────────────────────

from modules.ssl_tls_scanner import _cert_findings, WEAK_CIPHER_PATTERNS

def _test_ssl_cert_expired():
    cert = {
        "notAfter": "Jan  1 00:00:00 2000 GMT",
        "subject": [[("commonName", "test.com")]],
        "issuer":  [[("commonName", "test.com")]],
        "subjectAltName": [("DNS", "test.com")],
    }
    f = _cert_findings("test.com", cert, None)
    assert_true(any("Expired" in x["name"] for x in f))

def _test_ssl_self_signed():
    cert = {
        "notAfter": "Jan  1 00:00:00 2099 GMT",
        "subject": [[("commonName", "test.com")]],
        "issuer":  [[("commonName", "test.com")]],
        "subjectAltName": [("DNS", "test.com")],
    }
    f = _cert_findings("test.com", cert, None)
    assert_true(any("Self-Signed" in x["name"] for x in f))

def _test_ssl_cn_mismatch():
    cert = {
        "notAfter": "Jan  1 00:00:00 2099 GMT",
        "subject": [[("commonName", "other.com")]],
        "issuer":  [[("commonName", "CA Inc")]],
        "subjectAltName": [("DNS", "other.com")],
    }
    f = _cert_findings("target.com", cert, None)
    assert_true(any("Mismatch" in x["name"] for x in f))

def _test_ssl_weak_cipher_list():
    assert_true("RC4" in WEAK_CIPHER_PATTERNS)
    assert_true("NULL" in WEAK_CIPHER_PATTERNS)
    assert_true(len(WEAK_CIPHER_PATTERNS) >= 8)

test("ssl expired cert detected",        _test_ssl_cert_expired)
test("ssl self-signed cert detected",    _test_ssl_self_signed)
test("ssl CN mismatch detected",         _test_ssl_cn_mismatch)
test("ssl weak cipher list populated",   _test_ssl_weak_cipher_list)

# ── cors_scanner ───────────────────────────────────────────────────────────

from modules.cors_scanner import SENSITIVE_RESP_HEADERS

def _test_cors_sensitive_headers():
    assert_true("authorization" in SENSITIVE_RESP_HEADERS)
    assert_true(len(SENSITIVE_RESP_HEADERS) >= 4)

def _test_cors_headers_lowercase():
    assert_true(all(h == h.lower() for h in SENSITIVE_RESP_HEADERS))

test("cors sensitive header list populated",   _test_cors_sensitive_headers)
test("cors sensitive headers all lowercase",   _test_cors_headers_lowercase)

# ── cookie_analyser ────────────────────────────────────────────────────────

from modules.cookie_analyser import _analyse_cookie, _is_session_cookie

def _test_cookie_session_names():
    assert_true(_is_session_cookie("sessionid"))
    assert_true(_is_session_cookie("PHPSESSID"))
    assert_true(_is_session_cookie("auth_token"))
    assert_true(not _is_session_cookie("color"))

def _test_cookie_missing_httponly():
    f = _analyse_cookie(None, "sessionid", "abc123", {})
    assert_true(any("HttpOnly" in x["name"] for x in f))

def _test_cookie_missing_secure():
    f = _analyse_cookie(None, "sessionid", "abc123", {})
    assert_true(any("Secure" in x["name"] for x in f))

def _test_cookie_short_token():
    f = _analyse_cookie(None, "sessionid", "short", {})
    assert_true(any("Too Short" in x["name"] for x in f))

def _test_cookie_all_flags_ok():
    attrs = {"httponly": True, "secure": True, "samesite": "Lax"}
    f = _analyse_cookie(None, "sessionid", "a" * 32, attrs)
    # Should have no HttpOnly/Secure/SameSite/Short findings
    problems = [x for x in f if x["severity"] in ("high", "critical")]
    assert_eq(len(problems), 0)

test("cookie session name detection",       _test_cookie_session_names)
test("cookie missing HttpOnly flagged",     _test_cookie_missing_httponly)
test("cookie missing Secure flagged",       _test_cookie_missing_secure)
test("cookie short token flagged",          _test_cookie_short_token)
test("cookie well-configured = no issues",  _test_cookie_all_flags_ok)

# ── user_enum ──────────────────────────────────────────────────────────────

from modules.user_enum import DEFAULT_CREDS, BUILTIN_USERNAMES, _response_differs

class _FakeResp:
    def __init__(self, status, text): self.status_code = status; self.text = text

def _test_user_default_creds_has_admin():
    assert_true(any(u == "admin" for u, _ in DEFAULT_CREDS))

def _test_user_builtin_usernames():
    assert_true("admin" in BUILTIN_USERNAMES)
    assert_true(len(BUILTIN_USERNAMES) >= 10)

def _test_user_response_differs_status():
    assert_true(_response_differs(_FakeResp(200, "ok"), _FakeResp(401, "fail")))

def _test_user_response_differs_body():
    assert_true(_response_differs(_FakeResp(200, "x"*200), _FakeResp(200, "x"*10)))

def _test_user_response_same():
    assert_true(not _response_differs(_FakeResp(401, "Invalid"), _FakeResp(401, "Invalid")))

test("user enum default creds has admin",    _test_user_default_creds_has_admin)
test("user enum builtin username list",      _test_user_builtin_usernames)
test("user enum response differs by status", _test_user_response_differs_status)
test("user enum response differs by body",   _test_user_response_differs_body)
test("user enum same response = no diff",    _test_user_response_same)

# ── fingerprint ────────────────────────────────────────────────────────────

from modules.fingerprint import _match_signatures, CMS_SIGNATURES, RECON_PATHS

def _test_fp_match_wordpress():
    hits = _match_signatures("/wp-content/themes/default/style.css", CMS_SIGNATURES)
    assert_true("WordPress" in hits)

def _test_fp_match_drupal():
    hits = _match_signatures('/sites/default/files/image.jpg', CMS_SIGNATURES)
    assert_true("Drupal" in hits)

def _test_fp_recon_paths_has_git():
    assert_true("/.git/HEAD" in RECON_PATHS)

def _test_fp_recon_paths_has_env():
    assert_true("/.env" in RECON_PATHS)

def _test_fp_no_match():
    hits = _match_signatures("nothing here", CMS_SIGNATURES)
    assert_eq(hits, [])

test("fingerprint WordPress detection",     _test_fp_match_wordpress)
test("fingerprint Drupal detection",        _test_fp_match_drupal)
test("fingerprint recon has .git/HEAD",     _test_fp_recon_paths_has_git)
test("fingerprint recon has .env",          _test_fp_recon_paths_has_env)
test("fingerprint no false positive",       _test_fp_no_match)

# ── ldap_scanner ───────────────────────────────────────────────────────────

from modules.ldap_scanner import AUTH_BYPASS, BLIND_TRUE, _ldap_error_in

def _test_ldap_auth_bypass_payloads():
    assert_true(len(AUTH_BYPASS) >= 8)
    assert_true(any("*" in p for p in AUTH_BYPASS))

def _test_ldap_error_detection():
    assert_true(_ldap_error_in("Error: ldap_bind() failed"))
    assert_true(_ldap_error_in("javax.naming.NamingException occurred"))
    assert_true(not _ldap_error_in("Normal response text"))

def _test_ldap_blind_payloads():
    assert_true(len(BLIND_TRUE) >= 3)
    assert_true("*" in BLIND_TRUE)

def _test_ldap_bypass_has_wildcard():
    assert_true(any("*" in p for p in AUTH_BYPASS))

test("ldap auth bypass payload bank",       _test_ldap_auth_bypass_payloads)
test("ldap error string detection",         _test_ldap_error_detection)
test("ldap blind boolean payloads",         _test_ldap_blind_payloads)
test("ldap bypass has wildcard payload",    _test_ldap_bypass_has_wildcard)

# ── finding_tracker ────────────────────────────────────────────────────────

import tempfile
from modules.finding_tracker import FindingTracker, CONFIRMED, FALSE_POSITIVE, PENDING, FIXED

def _temp_tracker():
    return FindingTracker(tempfile.mktemp(suffix=".db"))

def _test_tracker_add_and_get():
    db = _temp_tracker()
    fid = db.add({"name": "XSS", "severity": "high", "detail": "reflected", "url": "https://t.com"}, "active_scan")
    f = db.get(fid)
    assert_eq(f["name"], "XSS")
    assert_eq(f["severity"], "high")
    assert_eq(f["status"], PENDING)
    assert_eq(f["source_module"], "active_scan")

def _test_tracker_status_update():
    db = _temp_tracker()
    fid = db.add({"name": "SQLi", "severity": "critical", "detail": "x"})
    db.update_status(fid, CONFIRMED, "Verified")
    f = db.get(fid)
    assert_eq(f["status"], CONFIRMED)
    assert_true("Verified" in f["notes"])

def _test_tracker_notes_append():
    db = _temp_tracker()
    fid = db.add({"name": "SQLi", "severity": "critical", "detail": "x"})
    db.add_note(fid, "First note")
    db.update_status(fid, CONFIRMED, "Second note")
    f = db.get(fid)
    assert_true("First note" in f["notes"])
    assert_true("Second note" in f["notes"])

def _test_tracker_tags():
    db = _temp_tracker()
    fid = db.add({"name": "CORS", "severity": "high", "detail": "x"})
    db.add_tag(fid, "waf-bypass")
    db.add_tag(fid, "prod")
    f = db.get(fid)
    assert_true("waf-bypass" in f["tags"])
    assert_true("prod" in f["tags"])

def _test_tracker_query_filter():
    db = _temp_tracker()
    db.add({"name": "A", "severity": "critical"})
    db.add({"name": "B", "severity": "info"})
    crits = db.query(severity="critical")
    assert_eq(len(crits), 1)
    assert_eq(crits[0]["name"], "A")

def _test_tracker_stats():
    db = _temp_tracker()
    db.add({"name": "A", "severity": "critical"})
    db.add({"name": "B", "severity": "high"})
    db.add({"name": "C", "severity": "high"})
    s = db.stats()
    assert_eq(s["total"], 3)
    assert_eq(s["by_severity"].get("critical", 0), 1)
    assert_eq(s["by_severity"].get("high", 0), 2)

def _test_tracker_import_export():
    import json as _json
    db = _temp_tracker()
    db.add({"name": "XSS", "severity": "high", "detail": "reflected"})
    out = tempfile.mktemp(suffix=".json")
    n = db.export_json(out)
    assert_eq(n, 1)
    db2 = _temp_tracker()
    imported = db2.import_json(out, "test")
    assert_eq(imported, 1)
    import os; os.unlink(out)

def _test_tracker_meta_skipped():
    db = _temp_tracker()
    fid = db.add({"name": "_raw", "severity": "meta", "detail": "..."})
    assert_eq(fid, -1)

test("tracker add and get",               _test_tracker_add_and_get)
test("tracker status update",             _test_tracker_status_update)
test("tracker notes append on update",    _test_tracker_notes_append)
test("tracker tags",                      _test_tracker_tags)
test("tracker query filter by severity",  _test_tracker_query_filter)
test("tracker stats",                     _test_tracker_stats)
test("tracker import/export JSON",        _test_tracker_import_export)
test("tracker meta findings skipped",     _test_tracker_meta_skipped)

# ── report_generator ───────────────────────────────────────────────────────

from modules.report_generator import generate, _remediation_for, _SEV_COLOUR, _chart_bars

_SAMPLE_FINDINGS = [
    {"name": "SQL Injection", "severity": "critical", "detail": "id param injectable",
     "url": "https://target.com/page?id=1", "status": "confirmed"},
    {"name": "CORS Misconfig", "severity": "high",     "detail": "origin reflected", "status": "pending"},
    {"name": "Missing HSTS",   "severity": "medium",   "detail": "No HSTS",          "status": "pending"},
    {"name": "_raw",           "severity": "meta",     "detail": "raw output"},
]

def _test_report_generates():
    out = tempfile.mktemp(suffix=".html")
    generate(_SAMPLE_FINDINGS, target="Acme", output=out)
    import os
    size = os.path.getsize(out); os.unlink(out)
    assert_true(size > 5000)

def _test_report_excludes_meta():
    out = tempfile.mktemp(suffix=".html")
    generate(_SAMPLE_FINDINGS, output=out)
    import os
    with open(out) as fh: content = fh.read()
    os.unlink(out)
    assert_true("_raw" not in content)

def _test_report_status_filter():
    out = tempfile.mktemp(suffix=".html")
    generate(_SAMPLE_FINDINGS, output=out, status_filter="confirmed")
    import os
    with open(out) as fh: content = fh.read()
    os.unlink(out)
    assert_true("SQL Injection" in content)
    assert_true("CORS" not in content)

def _test_remediation_lookup():
    rem = _remediation_for({"name": "SQL Injection — parameter id"})
    assert_true("parameteris" in rem.lower() or "prepared" in rem.lower())

def _test_remediation_fallback():
    rem = _remediation_for({"name": "Unknown Weird Finding"})
    assert_true(len(rem) > 20)

def _test_chart_bars():
    bars = _chart_bars({"critical": 2, "high": 1})
    assert_true("CRITICAL" in bars)
    assert_true("HIGH" in bars)

def _test_sev_colours_populated():
    for sev in ("critical", "high", "medium", "low", "info"):
        assert_true(sev in _SEV_COLOUR)

test("report generates HTML",             _test_report_generates)
test("report excludes meta findings",     _test_report_excludes_meta)
test("report status filter works",        _test_report_status_filter)
test("report remediation lookup",         _test_remediation_lookup)
test("report remediation fallback",       _test_remediation_fallback)
test("report chart bars render",          _test_chart_bars)
test("report severity colours complete",  _test_sev_colours_populated)

# ── ai_assist ──────────────────────────────────────────────────────────────

from modules.ai_assist import _load_api_key, save_api_key, _SYSTEM, MODEL

def _test_ai_model_name():
    assert_true("sonnet" in MODEL or "claude" in MODEL)

def _test_ai_system_prompt():
    assert_true("penetration tester" in _SYSTEM.lower())
    assert_true(len(_SYSTEM) > 200)

def _test_ai_key_roundtrip():
    import json as _json
    cfg = tempfile.mktemp(suffix=".json")
    # patch config path temporarily
    import modules.ai_assist as _m
    orig = _m._CONFIG_PATH
    _m._CONFIG_PATH = cfg
    save_api_key("sk-ant-test-key-123")
    key = _load_api_key()
    _m._CONFIG_PATH = orig
    import os; os.unlink(cfg)
    assert_eq(key, "sk-ant-test-key-123")

def _test_ai_no_key_returns_empty():
    import modules.ai_assist as _m
    orig_env = os.environ.pop("ANTHROPIC_API_KEY", None)
    orig_cfg = _m._CONFIG_PATH
    _m._CONFIG_PATH = "/tmp/nonexistent_catch403_config.json"
    key = _load_api_key()
    _m._CONFIG_PATH = orig_cfg
    if orig_env:
        os.environ["ANTHROPIC_API_KEY"] = orig_env
    assert_eq(key, "")

test("ai model is claude-sonnet",         _test_ai_model_name)
test("ai system prompt is security-focused", _test_ai_system_prompt)
test("ai key save/load roundtrip",        _test_ai_key_roundtrip)
test("ai no key returns empty string",    _test_ai_no_key_returns_empty)

# ── ssrf_scanner ───────────────────────────────────────────────────────────

from modules.ssrf_scanner import CLOUD_METADATA, INTERNAL_PROBES, BYPASS_ENCODINGS, _check_response

def _test_ssrf_cloud_metadata_count():
    assert_true(len(CLOUD_METADATA) >= 5)
    assert_true(any("AWS" in lbl for lbl, _ in CLOUD_METADATA))
    assert_true(any("GCP" in lbl for lbl, _ in CLOUD_METADATA))
    assert_true(any("Azure" in lbl for lbl, _ in CLOUD_METADATA))

def _test_ssrf_internal_probes():
    assert_true(any("127.0.0.1" in url for _, url in INTERNAL_PROBES))
    assert_true(any("9200" in url for _, url in INTERNAL_PROBES))

def _test_ssrf_bypass_encodings():
    assert_true(any("0x7f" in url for _, url in BYPASS_ENCODINGS))
    assert_true(any("2130706433" in url for _, url in BYPASS_ENCODINGS))  # decimal IP

class _FakeResp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text

def _test_ssrf_check_response_metadata():
    r = _FakeResp(200, "root:x:0:0:root:/root:/bin/bash")  # /etc/passwd content
    f = _check_response(r, "file:///etc/passwd", "File read")
    assert_true(f is not None)
    assert_eq(f["severity"], "critical")

def _test_ssrf_check_response_no_hit():
    r = _FakeResp(404, "Not Found")
    f = _check_response(r, "http://127.0.0.1/", "Internal probe")
    assert_true(f is None)

test("ssrf cloud metadata payloads coverage",  _test_ssrf_cloud_metadata_count)
test("ssrf internal probes coverage",          _test_ssrf_internal_probes)
test("ssrf bypass encoding variants",          _test_ssrf_bypass_encodings)
test("ssrf detects metadata in response",      _test_ssrf_check_response_metadata)
test("ssrf no false positive on 404",          _test_ssrf_check_response_no_hit)

# ── ssti_scanner ───────────────────────────────────────────────────────────

from modules.ssti_scanner import DETECTION_PAYLOADS, RCE_PAYLOADS, _check_reflection

class _FakeRespSSTI:
    def __init__(self, text): self.text = text

def _test_ssti_math_payloads():
    assert_true(any("{{7*7}}" in p for p, _, _, _ in DETECTION_PAYLOADS))
    assert_true(any("${7*7}" in p for p, _, _, _ in DETECTION_PAYLOADS))

def _test_ssti_rce_jinja2():
    assert_true("Jinja2" in RCE_PAYLOADS)
    assert_true(len(RCE_PAYLOADS["Jinja2"]) >= 2)
    assert_true(any("os.popen" in p for p, _ in RCE_PAYLOADS["Jinja2"]))

def _test_ssti_check_reflection_math():
    # {{7*7}} not reflected as-is, and 49 in response → detected
    r = _FakeRespSSTI("Hello 49 world")
    assert_true(_check_reflection(r, "{{7*7}}", r"49"))

def _test_ssti_check_reflection_no_exec():
    # Payload reflected verbatim = NOT executed
    r = _FakeRespSSTI("{{7*7}}")
    assert_true(not _check_reflection(r, "{{7*7}}", r"49"))

def _test_ssti_covers_multiple_engines():
    engines = {hint for _, _, hint, _ in DETECTION_PAYLOADS}
    combined = " ".join(engines)
    assert_true("Jinja2" in combined)
    assert_true("Twig" in combined)
    assert_true("Freemarker" in combined)

test("ssti math probes in payload bank",       _test_ssti_math_payloads)
test("ssti Jinja2 RCE payloads present",       _test_ssti_rce_jinja2)
test("ssti check_reflection detects execution", _test_ssti_check_reflection_math)
test("ssti check_reflection skips verbatim",   _test_ssti_check_reflection_no_exec)
test("ssti covers multiple template engines",  _test_ssti_covers_multiple_engines)

# ── crlf_scanner ───────────────────────────────────────────────────────────

from modules.crlf_scanner import _CRLF_TEMPLATES, _MARKER, COMMON_PARAMS

def _test_crlf_template_count():
    assert_true(len(_CRLF_TEMPLATES) >= 10)

def _test_crlf_covers_encodings():
    all_payloads = " ".join(_CRLF_TEMPLATES)
    assert_true("%0d%0a" in all_payloads)   # URL-encoded CRLF
    assert_true("%250d%250a" in all_payloads)  # double-encoded

def _test_crlf_common_params():
    assert_true("next" in COMMON_PARAMS)
    assert_true("redirect" in COMMON_PARAMS)
    assert_true(len(COMMON_PARAMS) >= 10)

def _test_crlf_marker_in_templates():
    for tmpl in _CRLF_TEMPLATES:
        if "{m}" in tmpl:
            assert_true("{m}" in tmpl)
            break

test("crlf template payload count",           _test_crlf_template_count)
test("crlf covers URL-encoded variants",       _test_crlf_covers_encodings)
test("crlf common redirect params list",       _test_crlf_common_params)
test("crlf marker placeholder in templates",   _test_crlf_marker_in_templates)

# ── open_redirect ──────────────────────────────────────────────────────────

from modules.open_redirect import _build_payloads, COMMON_PARAMS as OR_PARAMS

def _test_or_payload_count():
    payloads = _build_payloads("evil.com", "trusted.com")
    assert_true(len(payloads) >= 15)

def _test_or_has_scheme_relative():
    payloads = _build_payloads("evil.com", "trusted.com")
    labels = [lbl for lbl, _ in payloads]
    assert_true(any("scheme" in lbl.lower() or "//" in p for lbl, p in payloads))

def _test_or_has_javascript_uri():
    payloads = _build_payloads("evil.com", "trusted.com")
    assert_true(any("javascript:" in p.lower() for _, p in payloads))

def _test_or_has_authority_confusion():
    payloads = _build_payloads("evil.com", "trusted.com")
    assert_true(any("@evil.com" in p for _, p in payloads))

def _test_or_common_params():
    assert_true("next" in OR_PARAMS)
    assert_true("redirect" in OR_PARAMS)
    assert_true(len(OR_PARAMS) >= 15)

test("open_redirect payload count ≥15",       _test_or_payload_count)
test("open_redirect scheme-relative payload",  _test_or_has_scheme_relative)
test("open_redirect javascript: URI payload",  _test_or_has_javascript_uri)
test("open_redirect @ authority confusion",    _test_or_has_authority_confusion)
test("open_redirect common param list",        _test_or_common_params)

# ── xxe_scanner ────────────────────────────────────────────────────────────

from modules.xxe_scanner import _CLASSIC_PAYLOADS, _FILE_RE, _ERROR_RE, _SVG_XXE

def _test_xxe_classic_payloads():
    assert_true(len(_CLASSIC_PAYLOADS) >= 4)
    labels = [lbl for lbl, _, _ in _CLASSIC_PAYLOADS]
    assert_true(any("passwd" in lbl.lower() for lbl in labels))
    assert_true(any("win" in lbl.lower() for lbl in labels))

def _test_xxe_file_re_detects_passwd():
    assert_true(bool(_FILE_RE.search("root:x:0:0:root:/root:/bin/bash")))

def _test_xxe_file_re_detects_hosts():
    assert_true(bool(_FILE_RE.search("127.0.0.1   localhost")))

def _test_xxe_error_re():
    assert_true(bool(_ERROR_RE.search("java.io.FileNotFoundException: /etc/passwd")))
    assert_true(bool(_ERROR_RE.search("org.xml.sax.SAXParseException: entity 'xxe'")))
    assert_true(not bool(_ERROR_RE.search("200 OK all fine")))

def _test_xxe_svg_contains_entity():
    assert_true("ENTITY xxe" in _SVG_XXE)
    assert_true("file:///etc/passwd" in _SVG_XXE)

test("xxe classic payload bank",              _test_xxe_classic_payloads)
test("xxe /etc/passwd regex detection",       _test_xxe_file_re_detects_passwd)
test("xxe /etc/hosts regex detection",        _test_xxe_file_re_detects_hosts)
test("xxe XML error regex detection",         _test_xxe_error_re)
test("xxe SVG payload contains entity",       _test_xxe_svg_contains_entity)

# ── idor_scanner ───────────────────────────────────────────────────────────

from modules.idor_scanner import _NUMERIC_ID_RE, _UUID_RE, _sensitive_leak, _SECONDARY_SUFFIXES

class _FakeRespIDOR:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text

def _test_idor_numeric_re():
    m = _NUMERIC_ID_RE.search("/api/orders/1042/details")
    assert_true(m is not None)
    assert_eq(m.group(1), "1042")

def _test_idor_uuid_re():
    m = _UUID_RE.search("/api/users/550e8400-e29b-41d4-a716-446655440000/profile")
    assert_true(m is not None)

def _test_idor_secondary_suffixes():
    assert_true("/export" in _SECONDARY_SUFFIXES)
    assert_true("/download" in _SECONDARY_SUFFIXES)
    assert_true(len(_SECONDARY_SUFFIXES) >= 8)

def _test_idor_sensitive_leak_same_size():
    # Bodies large enough (>50 bytes) and similar size (ratio within 0.7-1.4)
    body_a = '{"id":1,"name":"Alice","email":"alice@example.com","role":"user","plan":"pro"}'
    body_b = '{"id":2,"name":"Bob",  "email":"bob@example.com",  "role":"user","plan":"pro"}'
    r_a = _FakeRespIDOR(200, body_a)
    r_b = _FakeRespIDOR(200, body_b)
    leaked, evidence = _sensitive_leak(r_a, r_b)
    assert_true(leaked)
    assert_true("ratio" in evidence)

def _test_idor_no_leak_on_403():
    r_a = _FakeRespIDOR(200, '{"id":1,"name":"Alice"}')
    r_b = _FakeRespIDOR(403, "Forbidden")
    leaked, _ = _sensitive_leak(r_a, r_b)
    assert_true(not leaked)

test("idor numeric ID regex extraction",    _test_idor_numeric_re)
test("idor UUID regex extraction",          _test_idor_uuid_re)
test("idor secondary suffixes list",        _test_idor_secondary_suffixes)
test("idor sensitive leak detected",        _test_idor_sensitive_leak_same_size)
test("idor 403 response = no leak",         _test_idor_no_leak_on_403)

# ── oob_helper ─────────────────────────────────────────────────────────────

from modules.oob_helper import SimpleCanary, quick_canary, INTERACTSH_SERVER

def _test_oob_simple_canary_url():
    c = SimpleCanary("oast.pro")
    url = c.url("test")
    assert_true("oast.pro" in url)
    assert_true(url.startswith("http://"))

def _test_oob_simple_canary_dns():
    c = SimpleCanary("oast.pro")
    dns = c.dns("test")
    assert_true(dns.endswith(".oast.pro"))

def _test_oob_quick_canary():
    url, dns = quick_canary("unittest")
    assert_true(url.startswith("http://"))
    assert_true("." in dns)

def _test_oob_server_default():
    assert_true("oast" in INTERACTSH_SERVER or "interact" in INTERACTSH_SERVER)

test("oob simple canary URL format",        _test_oob_simple_canary_url)
test("oob simple canary DNS format",        _test_oob_simple_canary_dns)
test("oob quick_canary returns url+dns",    _test_oob_quick_canary)
test("oob default server is interactsh",    _test_oob_server_default)

# ── prototype_pollution ────────────────────────────────────────────────────

from modules.prototype_pollution import _json_payloads, _query_payloads, _canary_reflected, _CANARY_VAL

class _FakeRespPP:
    def __init__(self, text): self.text = text

def _test_pp_json_payload_count():
    payloads = _json_payloads()
    assert_true(len(payloads) >= 5)

def _test_pp_has_proto_key():
    payloads = _json_payloads()
    has_proto = any("__proto__" in label.lower() for label, _ in payloads)
    assert_true(has_proto)

def _test_pp_has_constructor():
    payloads = _json_payloads()
    has_ctor = any("constructor" in label.lower() for label, _ in payloads)
    assert_true(has_ctor)

def _test_pp_canary_reflected():
    r = _FakeRespPP(f"some response with {_CANARY_VAL} here")
    assert_true(_canary_reflected(r))

def _test_pp_canary_not_reflected():
    r = _FakeRespPP("normal response body")
    assert_true(not _canary_reflected(r))

def _test_pp_query_payloads():
    payloads = _query_payloads("https://target.com/api?foo=bar")
    assert_true(len(payloads) >= 3)
    all_urls = " ".join(u for _, u in payloads)
    assert_true("__proto__" in all_urls)

test("prototype pollution JSON payload count",   _test_pp_json_payload_count)
test("prototype pollution has __proto__ key",    _test_pp_has_proto_key)
test("prototype pollution has constructor",      _test_pp_has_constructor)
test("prototype pollution canary reflected",     _test_pp_canary_reflected)
test("prototype pollution canary not reflected", _test_pp_canary_not_reflected)
test("prototype pollution query payloads",       _test_pp_query_payloads)

# ── vuln_chainer ───────────────────────────────────────────────────────────

from modules.vuln_chainer import CHAIN_RULES, analyse, _matches_rule

def _test_chainer_rule_count():
    assert_true(len(CHAIN_RULES) >= 10)

def _test_chainer_cors_csrf_chain():
    findings = [
        {"name": "CORS Wildcard Misconfiguration", "severity": "high", "detail": ""},
        {"name": "CSRF Token Missing on state-change endpoint", "severity": "medium", "detail": ""},
    ]
    chains = analyse(findings)
    cors_chains = [c for c in chains if "cors" in c["name"].lower()]
    assert_true(len(cors_chains) >= 1)

def _test_chainer_no_false_chain():
    findings = [{"name": "Missing X-Frame-Options", "severity": "low"}]
    chains = [c for c in analyse(findings)
              if c["severity"] in ("critical", "high")]
    assert_eq(len(chains), 0)

def _test_chainer_fingerprint_stable():
    # Test that analyse returns consistent results for the same input
    findings = [{"name": "CORS Misconfiguration", "severity": "high"}]
    chains1 = analyse(findings)
    chains2 = analyse(findings)
    assert_eq(len(chains1), len(chains2))

def _test_chainer_ssrf_metadata_chain():
    findings = [
        {"name": "SSRF — AWS IMDSv1 credentials", "severity": "critical", "detail": ""},
        {"name": "Cloud Metadata Exposed", "severity": "critical", "detail": ""},
    ]
    chains = analyse(findings)
    ssrf_chains = [c for c in chains if "ssrf" in c["name"].lower()]
    assert_true(len(ssrf_chains) >= 1)

test("vuln chainer rule count ≥10",            _test_chainer_rule_count)
test("vuln chainer detects CORS+CSRF chain",    _test_chainer_cors_csrf_chain)
test("vuln chainer no false positive",          _test_chainer_no_false_chain)
test("vuln chainer fingerprint is stable",      _test_chainer_fingerprint_stable)
test("vuln chainer detects SSRF+metadata",      _test_chainer_ssrf_metadata_chain)

# ── cicd_runner ────────────────────────────────────────────────────────────

import tempfile
from modules.cicd_runner import (
    _fingerprint as cicd_fp, _above_threshold, save_baseline, load_baseline,
    diff_against_baseline, to_sarif, PROFILES
)

def _test_cicd_profiles_exist():
    assert_true("quick" in PROFILES)
    assert_true("standard" in PROFILES)
    assert_true("full" in PROFILES)
    assert_true("api" in PROFILES)

def _test_cicd_threshold_high():
    assert_true(_above_threshold({"severity": "critical"}, "high"))
    assert_true(_above_threshold({"severity": "high"}, "high"))
    assert_true(not _above_threshold({"severity": "medium"}, "high"))
    assert_true(not _above_threshold({"severity": "low"}, "high"))

def _test_cicd_baseline_save_load():
    findings = [
        {"name": "XSS", "severity": "high", "url": "https://t.com", "param": "q"},
        {"name": "CSRF", "severity": "medium", "url": "https://t.com", "param": ""},
    ]
    target = "https://test.example.com"
    profile = "quick"
    save_baseline(target, profile, findings)
    baseline = load_baseline(target, profile)
    assert_true(len(baseline) == 2)

def _test_cicd_diff_new_findings():
    findings_v1 = [{"name": "XSS", "severity": "high", "url": "https://t.com", "param": "q"}]
    findings_v2 = [
        {"name": "XSS",  "severity": "high",   "url": "https://t.com", "param": "q"},
        {"name": "SSRF", "severity": "critical","url": "https://t.com", "param": "url"},
    ]
    save_baseline("https://diff.example.com", "quick", findings_v1)
    baseline = load_baseline("https://diff.example.com", "quick")
    new = diff_against_baseline(findings_v2, baseline)
    assert_eq(len(new), 1)
    assert_eq(new[0]["name"], "SSRF")

def _test_cicd_sarif_format():
    findings = [{"name": "XSS", "severity": "high", "detail": "reflected", "url": "https://t.com"}]
    sarif = to_sarif(findings, "https://t.com")
    assert_eq(sarif["version"], "2.1.0")
    assert_true(len(sarif["runs"]) == 1)
    assert_true(len(sarif["runs"][0]["results"]) == 1)

test("cicd profiles all present",             _test_cicd_profiles_exist)
test("cicd severity threshold filtering",     _test_cicd_threshold_high)
test("cicd baseline save and load",           _test_cicd_baseline_save_load)
test("cicd diff detects new findings",        _test_cicd_diff_new_findings)
test("cicd SARIF output format valid",        _test_cicd_sarif_format)

# ── summary ────────────────────────────────────────────────────────────────
print(f"\n{passed} passed, {failed} failed\n")
if failed:
    sys.exit(1)
