"""Who is asserting the claim?

A vulnerability report is two documents in one: prose making claims about the
project, and the reporter's own artifacts -- proof-of-concept source, server
stubs, build scripts -- which make no claims about it at all. Measured across
557 curl reports, 60% of every surviving contradiction came from the second
kind, and the tool was telling reporters their own exploit code was not part
of curl.

The split is not "inside a fence" versus "outside": stack traces live inside
fences 4.5:1 over prose, and a frame naming a function and a file is the
highest-quality claim a report ever makes.
"""
import pytest

from slopcheck.claims import extract


def kinds(claims, kind):
    return {c.value for c in claims if c.kind == kind}


POC = """\
The bug is in `lib/urlapi.c`.

```c
// my proof of concept
static char *create_pattern(int size) {
  char *p = malloc(size + 1);
  return p;
}
int main(void) { create_pattern(64); }
```
"""


def test_poc_symbols_are_not_extracted():
    """create_pattern is the reporter's function. It is absent from every
    project's tree by construction, and flagging it is a category error."""
    c = extract(POC)
    assert "create_pattern" not in kinds(c, "symbol")


def test_prose_symbols_still_are():
    assert "Curl_ossl_strerror" in kinds(
        extract("The fault is in `Curl_ossl_strerror()` on entry."), "symbol")


ASAN = """\
Reproduced under ASan:

```text
    #0 0x55cc37b1541c in state_performing /tmp/repro/curl/lib/multi.c:1915:12
    #1 0x55cc37b08449 in multi_runsingle /tmp/repro/curl/lib/multi.c:2100:5
```
"""


def test_stack_frames_inside_a_fence_are_extracted():
    """The single highest-value claim shape in the corpus. A blanket 'skip
    fenced blocks' rule would discard 27 of the 33 stack traces in it."""
    c = extract(ASAN)
    assert "state_performing" in kinds(c, "symbol")
    assert "tmp/repro/curl/lib/multi.c" in kinds(c, "path")
    assert "1915" in kinds(c, "line")


VALGRIND = """\
```
==5247==    by 0x48AF420: push_promise (http2.c:877)
```
"""


def test_valgrind_frames_are_extracted():
    c = extract(VALGRIND)
    assert "push_promise" in kinds(c, "symbol")
    assert "877" in kinds(c, "line")


DIFF = """\
```diff
diff --git a/lib/vtls/x509asn1.c b/lib/vtls/x509asn1.c
index cea88e668..ddfb65344 100644
--- a/lib/vtls/x509asn1.c
+++ b/lib/vtls/x509asn1.c
@@ -65,13 +65,13 @@
```
"""


def test_diff_headers_give_paths_but_not_blob_hashes():
    """`index cea88e668..ddfb65344` names two blobs. Reading them as commit
    references contradicted the reporter on every diff in the corpus."""
    c = extract(DIFF)
    assert any("x509asn1.c" in p for p in kinds(c, "path"))
    assert kinds(c, "commit") == set()


LOGS = """\
```
[thread: 7bdde700] multi_done(data = 0x623000206108)
[176771.791272] curl[132987]: segfault at 5 ip 00007f3a8db8b75d sp 00007ffd419fd958
```
"""


def test_debug_log_hex_is_not_a_commit():
    """Thread ids and register dumps are not commit references."""
    assert extract(LOGS) == [] or kinds(extract(LOGS), "commit") == set()


def test_prose_commit_reference_survives():
    c = extract("Introduced by commit `a78a07d3a9` (cookie: cleanups).")
    assert "a78a07d3a9" in kinds(c, "commit")


def test_abbreviated_hash_is_never_a_symbol():
    """a78a07d3a9 is a real curl commit. Every one of the 42 distinct hex
    'symbols' in the corpus resolved to one, and each was reported as a
    nonexistent identifier."""
    c = extract("Introduced by commit `a78a07d3a9` (cookie: cleanups).")
    assert "a78a07d3a9" not in kinds(c, "symbol")


def test_known_basenames_admit_a_bare_path_line_reference():
    text = "```\nsee lib/multi.c:1915 for the write\n```"
    assert "1915" in kinds(extract(text, {"multi.c"}), "line")


def test_diff_prefixes_are_stripped():
    """a/ and b/ are diff syntax. Reading them as directories turned every
    patch in a report into a wrong-directory contradiction."""
    c = extract(DIFF, {"x509asn1.c"})
    assert "lib/vtls/x509asn1.c" in kinds(c, "path")
    assert not any(p.startswith(("a/", "b/")) for p in kinds(c, "path"))


THIRD_PARTY_FRAMES = """\
```
    #0 0x7967a543daa6 in __interceptor_strlen
    #5 0x561a091034f5 in CRYPTO_strdup /src/openssl_external/crypto/o_str.c:28:11
    #1 0x7967a51a4326 in readback_bytes lib/mime.c:683:3
```
"""


def test_frame_symbols_require_a_file_in_this_tree():
    """curl links OpenSSL, glibc and wolfSSL. A trace is mostly not curl
    frames, and the sanitiser's own runtime is never a claim about curl."""
    c = extract(THIRD_PARTY_FRAMES, {"mime.c"})
    assert "readback_bytes" in kinds(c, "symbol")
    assert "__interceptor_strlen" not in kinds(c, "symbol")
    assert "CRYPTO_strdup" not in kinds(c, "symbol")
    assert not any("openssl_external" in p for p in kinds(c, "path"))
