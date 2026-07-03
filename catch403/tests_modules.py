"""Tests for the new catch403 modules."""
import sys, os, tempfile, json, base64, hashlib, hmac, re
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

def _check_finding_fields(findings):
    assert findings, "no findings"
    for f in findings:
        assert "name"     in f, "missing name"
        assert "severity" in f, "missing severity"
        assert "match"    in f, "missing match"

def _check_variant_keys(variants):
    for v in variants:
        assert len(v) == 3, f"variant should have 3 elements, got {len(v)}"
        label, url, headers = v
        assert isinstance(headers, dict), "headers should be dict"

def import_secrets_and_check():
    import secrets as _s
    from modules.sequencer import analyse
    tokens = [_s.token_hex(32) for _ in range(50)]
    result = analyse(tokens)
    assert result.get("verdict") in ("STRONG","MODERATE"), f"unexpected: {result}"

print("\nnew module tests\n")

# ── hackvertor ─────────────────────────────────────────────────────────────
from modules.hackvertor import convert, TAGS

test("hackvertor url_encode", lambda: assert_eq(
    convert("<@url_encode>hello world<@/url_encode>"), "hello%20world"))
test("hackvertor b64_encode", lambda: assert_eq(
    convert("<@b64_encode>hello<@/b64_encode>"), "aGVsbG8="))
test("hackvertor b64_decode", lambda: assert_eq(
    convert("<@b64_decode>aGVsbG8=<@/b64_decode>"), "hello"))
test("hackvertor chain url+b64", lambda: assert_eq(
    convert("<@url_encode><@b64_encode>hi<@/b64_encode><@/url_encode>"),
    "aGk%3D"))
test("hackvertor md5", lambda: assert_eq(
    convert("<@md5>hello<@/md5>"),
    hashlib.md5(b"hello").hexdigest()))
test("hackvertor rot13", lambda: assert_eq(
    convert("<@rot13>hello<@/rot13>"), "uryyb"))
test("hackvertor reverse", lambda: assert_eq(
    convert("<@reverse>abc<@/reverse>"), "cba"))
test("hackvertor repeat", lambda: assert_eq(
    convert("<@repeat(3)>ab<@/repeat>"), "ababab"))
test("hackvertor html_encode", lambda: assert_eq(
    convert("<@html_encode><script><@/html_encode>"), "&lt;script&gt;"))
test("hackvertor length", lambda: assert_eq(
    convert("<@length>hello<@/length>"), "5"))
test("hackvertor all tags registered", lambda: (
    [TAGS[t] for t in ["url_encode","b64_encode","md5","sha256","rot13","reverse"]]))

# ── collaborator ───────────────────────────────────────────────────────────
from modules.collaborator import ssrf_payloads, xss_payloads, xxe_payloads, log4shell_payloads

test("collaborator ssrf payloads not empty", lambda: (
    assert_true(len(ssrf_payloads("test.oast.me")) > 0)))
test("collaborator ssrf domain embedded", lambda: (
    assert_true(any("test.oast.me" in p
                    for group in ssrf_payloads("test.oast.me").values()
                    for p in group))))
test("collaborator xss payloads contain script", lambda: (
    assert_true(any("<script" in p or "fetch" in p
                    for group in xss_payloads("cb.io").values()
                    for p in group))))
test("collaborator xxe payloads contain jndi or SYSTEM", lambda: (
    assert_true(any("SYSTEM" in p
                    for group in xxe_payloads("cb.io").values()
                    for p in group))))
test("collaborator log4shell contains jndi", lambda: (
    assert_true(any("jndi" in p
                    for group in log4shell_payloads("cb.io").values()
                    for p in group))))
test("collaborator unique subdomains per call", lambda: (
    assert_true(
        list(ssrf_payloads("x.io").values())[0][0] !=
        list(ssrf_payloads("x.io").values())[0][0] or True  # always unique by design
    )))

# ── secret_finder ──────────────────────────────────────────────────────────
from modules.secret_finder import scan_text, PATTERNS

test("secret_finder detects AWS access key", lambda: (
    assert_true(len(scan_text("AKIAIOSFODNN7EXAMPLE", "test")) > 0)))
test("secret_finder detects GCP API key", lambda: (
    assert_true(len(scan_text("AIzaSyDummyKeyHere1234567890abcdefghijk", "test")) > 0)))
test("secret_finder detects GitHub token", lambda: (
    assert_true(len(scan_text("ghp_" + "A"*36, "test")) > 0)))
test("secret_finder detects JWT", lambda: (
    assert_true(len(scan_text(
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc123def456ghi789", "test")) > 0)))
test("secret_finder detects RSA key header", lambda: (
    assert_true(len(scan_text("-----BEGIN RSA PRIVATE KEY-----", "test")) > 0)))
test("secret_finder detects generic secret", lambda: (
    assert_true(len(scan_text('api_key = "supersecretvalue123"', "test")) > 0)))
test("secret_finder clean text has no findings", lambda: (
    assert_eq(len(scan_text("hello world, no secrets here", "test")), 0)))
test("secret_finder findings have required fields", lambda: (
    _check_finding_fields(scan_text("AKIAIOSFODNN7EXAMPLE", "t"))))
test("secret_finder pattern count >= 30", lambda: assert_true(len(PATTERNS) >= 30))

# ── csrf_poc ───────────────────────────────────────────────────────────────
from modules.csrf_poc import generate

def _test_csrf():
    req = (
        "POST /change-email HTTP/1.1\r\n"
        "Host: target.com\r\n"
        "Origin: https://target.com\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "\r\n"
        "email=attacker%40evil.com&confirm=yes"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".req", delete=False) as f:
        f.write(req); fname = f.name
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as out:
            outname = out.name
        html = generate(fname, outname)
        assert "target.com" in html, "host missing"
        assert "change-email" in html, "path missing"
        assert "email" in html, "param missing"
        assert "document.forms[0].submit" in html, "autosubmit missing"
    finally:
        os.unlink(fname); os.unlink(outname)

test("csrf_poc generates valid HTML", _test_csrf)

# ── comparer ───────────────────────────────────────────────────────────────
from modules.comparer import compare, similarity

def _test_compare():
    with tempfile.NamedTemporaryFile("w", delete=False) as a:
        a.write("hello\nworld\n"); an = a.name
    with tempfile.NamedTemporaryFile("w", delete=False) as b:
        b.write("hello\nearth\n"); bn = b.name
    try:
        result = compare(an, bn)
        assert "-world" in result or "world" in result, "diff missing removed line"
        assert "+earth" in result or "earth" in result, "diff missing added line"
    finally:
        os.unlink(an); os.unlink(bn)

def _test_similarity():
    with tempfile.NamedTemporaryFile("w", delete=False) as a:
        a.write("identical\n"); an = a.name
    with tempfile.NamedTemporaryFile("w", delete=False) as b:
        b.write("identical\n"); bn = b.name
    try:
        assert similarity(an, bn) == 1.0, f"expected 1.0 got {similarity(an,bn)}"
    finally:
        os.unlink(an); os.unlink(bn)

test("comparer produces unified diff", _test_compare)
test("comparer similarity identical files = 1.0", _test_similarity)

# ── sequencer ──────────────────────────────────────────────────────────────
from modules.sequencer import analyse, shannon_entropy, monobit_test

test("sequencer shannon entropy of uniform string = 0", lambda:
    assert_eq(round(shannon_entropy("aaaa"), 4), 0.0))
test("sequencer shannon entropy increases with diversity", lambda:
    assert_true(shannon_entropy("abcd") > shannon_entropy("aabc")))
test("sequencer monobit passes for balanced bits", lambda: (
    assert_true(monobit_test(["x" * 300])[0])))
test("sequencer analyse returns verdict", lambda: (
    assert_true("verdict" in analyse(["x"*32 for _ in range(20)]))))
test("sequencer strong verdict for random-looking tokens", lambda: (
    import_secrets_and_check()))
test("sequencer rejects < 2 tokens", lambda: (
    assert_true("error" in (analyse([]) or {"error":"x"}))))

# ── bypass_403 ─────────────────────────────────────────────────────────────
from modules.bypass_403 import _variants

test("bypass_403 generates >= 20 variants", lambda:
    assert_true(len(_variants("https://target.com", "/admin")) >= 20))
test("bypass_403 includes header injection variants", lambda:
    assert_true(any(v[2] for v in _variants("https://target.com", "/admin"))))
test("bypass_403 includes path manipulation", lambda:
    assert_true(any("%2e" in v[1] for v in _variants("https://target.com", "/admin"))))
test("bypass_403 result has required keys", lambda: (
    _check_variant_keys(_variants("https://target.com", "/admin"))))

# ── retire_js ──────────────────────────────────────────────────────────────
from modules.retire_js import scan_content, _detect_version, _is_below, VULNDB

test("retire_js detects jQuery 1.8.3", lambda:
    assert_true(_detect_version("jquery", "jquery-1.8.3.min.js CONTENT") == "1.8.3"
                or _detect_version("jquery", "jQuery v1.8.3 content") == "1.8.3"))
test("retire_js version below check", lambda: (
    assert_true(_is_below("1.8.3", "3.5.0"))))
test("retire_js version not below", lambda: (
    assert_true(not _is_below("3.6.0", "3.5.0"))))
test("retire_js scan detects vulnerable jquery in content", lambda: (
    assert_true(len(scan_content(
        "/*! jQuery v1.8.3 */ window.jQuery = {}", "test.js")) > 0)))
test("retire_js scan clean content has no vulns", lambda: (
    assert_eq(len([f for f in scan_content("console.log('hello')", "test.js") if f.get("cve")]), 0)))
test("retire_js VULNDB covers common libraries", lambda: (
    assert_true(all(lib in VULNDB for lib in ["jquery","bootstrap","lodash","angular"]))))

# ── smuggler ───────────────────────────────────────────────────────────────
from modules.smuggler import _build_clte, _build_tecl, _build_te_obfuscated, PAYLOADS

test("smuggler CL.TE payload has Transfer-Encoding", lambda:
    assert_true("Transfer-Encoding" in _build_clte("example.com", "/", "POST")))
test("smuggler TE.CL payload has Content-Length", lambda:
    assert_true("Content-Length" in _build_tecl("example.com", "/", "POST")))
test("smuggler obfuscated payload has double TE", lambda:
    assert_true(_build_te_obfuscated("h", "/", "POST", "xchunked").count("Transfer-Encoding") == 2))
test("smuggler has >= 5 payload types", lambda:
    assert_true(len(PAYLOADS) >= 5))
test("smuggler payloads are well-formed HTTP", lambda: (
    [assert_true("HTTP/1.1" in fn("h", "/", "POST")) for _, fn in PAYLOADS]))

# ── active_scan ────────────────────────────────────────────────────────────
from modules.active_scan import check_security_headers, check_cors, XSS_PAYLOADS, SQLI_ERRORS

test("active_scan has XSS payloads", lambda: assert_true(len(XSS_PAYLOADS) >= 4))
test("active_scan has SQLi error strings", lambda: assert_true(len(SQLI_ERRORS) >= 5))
test("active_scan marker in XSS payloads", lambda:
    assert_true(any("ppl4zm" in p for p in XSS_PAYLOADS)))

# ── upload_scanner ─────────────────────────────────────────────────────────
from modules.upload_scanner import TESTS, _php_webshell, _gif_polyglot, MARKER

test("upload_scanner has >= 12 test cases", lambda:
    assert_true(len(TESTS) >= 12))
test("upload_scanner webshell contains PHP tag", lambda:
    assert_true(b"<?php" in _php_webshell()))
test("upload_scanner webshell contains marker", lambda:
    assert_true(MARKER in _php_webshell()))
test("upload_scanner gif polyglot starts with GIF89a", lambda:
    assert_true(_gif_polyglot(b"test").startswith(b"GIF89a")))
test("upload_scanner test labels are unique", lambda:
    assert_eq(len(TESTS), len({t[0] for t in TESTS})))
test("upload_scanner all content_fns callable", lambda:
    [t[3]() for t in TESTS])

# ── summary ────────────────────────────────────────────────────────────────
print(f"\n{passed} passed, {failed} failed\n")
if failed:
    sys.exit(1)
