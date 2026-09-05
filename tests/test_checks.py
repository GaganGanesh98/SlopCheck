"""End-to-end tests for the git-backed half: Tree and the six checks.

These build a throwaway repository rather than mocking git, because the checks
are almost entirely assertions about git's actual output format.
"""
import subprocess
import pytest

from slopcheck.claims import Claim
from slopcheck.checks import Tree, CONTRADICTED, CONSISTENT, UNCHECKABLE
from slopcheck import checks


def _git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), *args], check=True,
                   capture_output=True, text=True)


@pytest.fixture(scope="module")
def repo(tmp_path_factory):
    d = tmp_path_factory.mktemp("fixture")
    (d / "lib").mkdir()
    (d / "lib" / "openssl.c").write_text(
        "static char *Curl_ossl_strerror(int err)\n{\n  return NULL;\n}\n")
    _git(d, "init", "-q", ".")
    _git(d, "config", "user.email", "t@t")
    _git(d, "config", "user.name", "t")
    _git(d, "add", "-A")
    _git(d, "commit", "-qm", "initial")
    _git(d, "tag", "-a", "-m", "r", "curl-8_10_0")
    (d / "lib" / "openssl.c").write_text(
        (d / "lib" / "openssl.c").read_text() + "void Curl_ossl_close(void) {}\n")
    _git(d, "add", "-A")
    _git(d, "commit", "-qm", "add close")
    _git(d, "tag", "-a", "-m", "r", "curl-8_11_0")
    _git(d, "tag", "-a", "-m", "r", "curl-8_12_0")
    _git(d, "tag", "-a", "-m", "r", "curl-8_13_0")
    return d


@pytest.fixture
def tree(repo):
    return Tree(str(repo), "curl-8_13_0")


def test_resolve_ref_and_files(tree):
    assert tree.resolve_ref()
    assert "lib/openssl.c" in tree.files


def test_missing_ref_is_unresolvable(repo):
    assert Tree(str(repo), "curl-99_0_0").resolve_ref() is None


def test_path_present_is_consistent(tree):
    assert checks.check_path(tree, Claim("path", "lib/openssl.c")).verdict == CONSISTENT


def test_path_absent_is_contradicted(tree):
    f = checks.check_path(tree, Claim("path", "packages/OS400/os400sys.c"))
    assert f.verdict == CONTRADICTED


def test_relocated_path_names_where_it_actually_is(tree):
    f = checks.check_path(tree, Claim("path", "wrong/dir/openssl.c"))
    assert f.verdict == CONTRADICTED
    assert "lib/openssl.c" in f.observed


def test_bare_filename_is_uncheckable_not_contradicted(tree):
    """poc.c is the reporter's own file, not a claim about the project."""
    assert checks.check_path(tree, Claim("path", "poc.c")).verdict == UNCHECKABLE


def test_line_past_eof_is_contradicted(tree):
    f = checks.check_line(tree, Claim("line", "9000", extra={"path": "lib/openssl.c"}))
    assert f.verdict == CONTRADICTED


def test_line_in_range_is_consistent(tree):
    f = checks.check_line(tree, Claim("line", "2", extra={"path": "lib/openssl.c"}))
    assert f.verdict == CONSISTENT


def test_unbound_line_is_uncheckable(tree):
    assert checks.check_line(tree, Claim("line", "741")).verdict == UNCHECKABLE


def test_symbol_present_is_consistent(tree):
    assert checks.check_symbol(tree, Claim("symbol", "Curl_ossl_strerror")).verdict == CONSISTENT


def test_invented_symbol_is_contradicted(tree):
    assert checks.check_symbol(tree, Claim("symbol", "Curl_ldap_err2string")).verdict == CONTRADICTED


def test_symbol_absent_here_but_present_later_downgrades_to_uncheckable(repo):
    """Checking an 8.11 report against 8.10 is a stale --ref, not a fabrication."""
    t = Tree(str(repo), "curl-8_10_0")
    f = checks.check_symbol(t, Claim("symbol", "Curl_ossl_close"))
    assert f.verdict == UNCHECKABLE
    assert "--ref" in f.observed


def test_recent_tags_is_not_truncated_by_shared_prefix(tree):
    """Every curl tag starts 'curl-'; a prefix-keyed dedupe collapses them all."""
    assert len(tree.recent_tags()) == 4


def test_commit_checks(tree, repo):
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    assert checks.check_commit(tree, Claim("commit", head[:10])).verdict == CONSISTENT
    assert checks.check_commit(tree, Claim("commit", "deadbeef1234")).verdict == CONTRADICTED


def test_snippet_checks(tree):
    real = "static char *Curl_ossl_strerror(int err)"
    assert checks.check_snippet(tree, Claim("snippet", real)).verdict == CONSISTENT
    fake = "char *totally_invented_helper(int n) { return unchecked_alloc(n); }"
    assert checks.check_snippet(tree, Claim("snippet", fake)).verdict == CONTRADICTED


def test_version_tag_matching(tree):
    assert checks.check_version(tree, Claim("version", "8.11.0")).verdict == CONSISTENT
    assert checks.check_version(tree, Claim("version", "99.0.0")).verdict == UNCHECKABLE


def test_prerelease_tags_are_skipped_when_probing_history(tmp_path):
    """curl's four newest tags are 8_22_0 plus three of its own RCs; probing
    those covers one point in history, not four."""
    d = tmp_path / "rc"
    d.mkdir()
    (d / "f.c").write_text("int x;\n")
    _git(d, "init", "-q", ".")
    _git(d, "config", "user.email", "t@t")
    _git(d, "config", "user.name", "t")
    _git(d, "add", "-A")
    _git(d, "commit", "-qm", "c")
    for t in ("curl-8_20_0", "curl-8_21_0", "rc-8_22_0-1", "rc-8_22_0-2",
              "curl-8_22_0"):
        _git(d, "tag", "-a", "-m", "r", t)
    got = Tree(str(d), "HEAD").recent_tags()
    assert not [t for t in got if t.startswith("rc-")], got
