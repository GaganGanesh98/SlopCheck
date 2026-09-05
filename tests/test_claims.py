"""Regression tests for claim extraction.

The precision cases matter more than the recall cases: a false CONTRADICTED
costs the tool its credibility with the maintainer reading it, while a missed
claim costs nothing.
"""
from slopcheck.claims import extract


def kinds(text):
    return {(c.kind, c.value) for c in extract(text)}


def test_extracts_path_and_bound_line():
    got = kinds("crash in packages/OS400/os400sys.c:741 during parsing")
    assert ("path", "packages/OS400/os400sys.c") in got
    assert ("line", "741") in got


def test_binds_line_to_nearest_preceding_path():
    cs = extract("The file lib/vtls/openssl.c is affected. Vulnerable Lines: "
                 "Lines 741, 773, and 804.")
    lines = [c for c in cs if c.kind == "line"]
    assert {c.value for c in lines} == {"741", "773", "804"}
    assert all(c.extra.get("path") == "lib/vtls/openssl.c" for c in lines)


def test_extracts_called_symbol():
    assert ("symbol", "Curl_ldap_err2string") in kinds(
        "static char *Curl_ldap_err2string(char *cp, char *cp2)")


def test_english_prose_is_not_a_symbol():
    """'Remote Code Execution (RCE)' must not become a symbol claim."""
    got = {v for k, v in kinds(
        "carries a High potential for Remote Code Execution (RCE) by "
        "overwriting memory, confirmed with memory instrumentation (ASAN)")
        if k == "symbol"}
    assert "Execution" not in got
    assert "instrumentation" not in got


def test_stdlib_names_are_ignored():
    """Absence of strcpy from a project tree proves nothing about the report."""
    got = {v for k, v in kinds("the code calls strcpy(dst, src) unsafely")
           if k == "symbol"}
    assert "strcpy" not in got


def test_register_dumps_are_not_commit_hashes():
    """'rbx 0x7ffff7832be3 140737345956835' must not yield a commit claim."""
    got = {v for k, v in kinds("registers: rbx 0x7ffff7832be3 140737345956835")
           if k == "commit"}
    assert "140737345956835" not in got


def test_real_commit_hash_is_extracted():
    assert ("commit", "8071d7adc") in kinds("introduced in commit 8071d7adc")


def test_cve_and_version():
    got = kinds("CVE-2026-80229 affects curl 8.21.0 and earlier")
    assert ("cve", "CVE-2026-80229") in got
    assert ("version", "8.21.0") in got


def test_fenced_snippet_captured():
    text = "here:\n```c\nstatic void f(void) { memcpy(a, b, n); return; }\n```\n"
    assert any(c.kind == "snippet" for c in extract(text))


def test_vague_report_yields_no_checkable_claims():
    """An unfalsifiable report should surface as 'nothing to check'."""
    cs = extract("An attacker may be able to trigger undefined behaviour "
                 "leading to potential remote code execution.")
    assert not [c for c in cs if c.kind in ("path", "symbol", "commit")]


def test_ip_address_is_not_a_version():
    """'127.0.0.1:389' in a PoC transcript must not become a version claim."""
    got = {v for k, v in kinds("rogue LDAP server listening on 127.0.0.1:389")
           if k == "version"}
    assert got == set(), got


def test_dotted_versions_still_extracted():
    got = {v for k, v in kinds("affects curl 8.21.0, fixed in v8.22 and 9.0.0.")
           if k == "version"}
    assert got == {"8.21.0", "8.22", "9.0.0"}, got
