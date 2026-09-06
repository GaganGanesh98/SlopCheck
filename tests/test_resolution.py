"""Binding a reported path to a real one, and what happens when we cannot.

Stack traces carry the reporter's build directory (/tmp/repro/curl/lib/multi.c)
and valgrind prints bare basenames (ftp.c). Neither asserts that the project
ships that path; both name a file that is really there. Treating them as
disagreements produced 1,035 of the 1,859 contradictions on the curl corpus.
"""
import subprocess
import pytest

from slopcheck.claims import Claim
from slopcheck.checks import (Tree, check_path, check_line, check_symbol,
                              CONTRADICTED, CONSISTENT, UNCHECKABLE)


def _git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), *args], check=True,
                   capture_output=True, text=True)


@pytest.fixture(scope="module")
def repo(tmp_path_factory):
    d = tmp_path_factory.mktemp("res")
    (d / "lib").mkdir()
    (d / "lib" / "multi.c").write_text("".join(f"/* {i} */\n" for i in range(200)))
    _git(d, "init", "-q", ".")
    _git(d, "config", "user.email", "t@t")
    _git(d, "config", "user.name", "t")
    _git(d, "add", "-A")
    _git(d, "commit", "-qm", "initial")
    return d


@pytest.fixture
def tree(repo):
    return Tree(str(repo), "HEAD")


def p(v, **extra):
    return Claim("path", v, "ctx", extra)


def ln(v, path):
    return Claim("line", v, "ctx", {"path": path})


# --- paths ----------------------------------------------------------------

def test_build_prefix_is_consistent(tree):
    f = check_path(tree, p("tmp/repro/curl/lib/multi.c"))
    assert f.verdict == CONSISTENT
    assert "lib/multi.c" in f.observed


def test_bare_basename_is_consistent(tree):
    """valgrind prints 'multi.c'. No directory was asserted."""
    assert check_path(tree, p("multi.c")).verdict == CONSISTENT


def test_wrong_directory_still_contradicts(tree):
    """The reporter asserted a directory the file has never been in. This is
    the finding the tool exists to surface."""
    assert check_path(tree, p("include/multi.c")).verdict == CONTRADICTED


# --- lines ----------------------------------------------------------------

def test_line_resolves_through_a_build_prefix(tree):
    f = check_line(tree, ln("150", "tmp/repro/curl/lib/multi.c"))
    assert f.verdict == CONSISTENT
    assert "reported as" in f.observed


def test_line_past_eof_survives_resolution(tree):
    f = check_line(tree, ln("900", "tmp/repro/curl/lib/multi.c"))
    assert f.verdict == CONTRADICTED
    assert "lines long" in f.observed and "lib/multi.c" in f.observed


def test_unbindable_path_is_uncheckable_not_contradicted(tree):
    """Not reading the file is a statement about this tool's reach, not about
    the tree. 602 of 625 line contradictions on the curl corpus were this."""
    f = check_line(tree, ln("1490", "poc_b1_h2_push_oom_bypass.c"))
    assert f.verdict == UNCHECKABLE


def test_bare_basename_line_is_checked(tree):
    assert check_line(tree, ln("150", "multi.c")).verdict == CONSISTENT


# --- symbols --------------------------------------------------------------

def test_commit_hash_is_not_a_fabricated_symbol(tree, repo):
    """Second line of defence: the extractor declines to emit these, but if
    one arrives it must be answered, not contradicted."""
    sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "--short=10", "HEAD"],
                         capture_output=True, text=True).stdout.strip()
    f = check_symbol(tree, Claim("symbol", sha, "ctx"))
    assert f.verdict == CONSISTENT
    assert "commit" in f.observed
