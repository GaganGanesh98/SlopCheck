"""Regression tests for the stale-ref downgrade on the PATH axis.

The symbol axis got this safety net first; paths went without it, so a genuine
report about a file that has since moved came back CONTRADICTED. Fixing it is
not a copy of the symbol logic, because two different questions hide inside
"this file is missing":

  (a) did THIS EXACT path exist at an older release?  -> stale ref, downgrade
  (b) did a file with this BASENAME exist elsewhere?  -> context only

Conflating them would suppress the most useful finding the tool produces: a
reporter naming the right file in the wrong directory.
"""
import subprocess
import pytest

from slopcheck.checks import Tree, check_path, CONTRADICTED, UNCHECKABLE
from slopcheck.claims import Claim


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path):
    """Mirrors curl: a file that relocates between releases, plus a name that
    only ever lived in one directory."""
    r = tmp_path / "proj"
    (r / "old").mkdir(parents=True)
    git(r, "init", "-q")
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")

    # Long enough to clear check_snippet's 25-char distinctiveness floor: the
    # obvious one-liner (`int f(void){return 1;}`) is 22 chars, so a snippet
    # test against it would return UNCHECKABLE for a reason unrelated to what
    # it is meant to be checking.
    (r / "old" / "sys.c").write_text(
        "int parse_header_field(const char *buf, size_t len){return 1;}\n")
    (r / "old" / "only_here.h").write_text("#define X 1\n")
    git(r, "add", "-A"); git(r, "commit", "-q", "-m", "v1")
    for t in ("proj-1_0_0", "proj-1_1_0", "proj-1_2_0"):
        git(r, "tag", t)

    # relocate old/sys.c -> new/sys.c; delete only_here.h entirely
    (r / "new").mkdir()
    git(r, "mv", "old/sys.c", "new/sys.c")
    git(r, "rm", "-q", "old/only_here.h")
    git(r, "commit", "-q", "-m", "relocate")
    for t in ("proj-1_3_0", "proj-1_4_0"):
        git(r, "tag", t)
    return r


def claim(v):
    return Claim("path", v, "ctx")


def test_relocated_path_is_downgraded_not_contradicted(repo):
    """old/sys.c is gone at HEAD but was real at proj-1_2_0."""
    f = check_path(Tree(str(repo)), claim("old/sys.c"))
    assert f.verdict == UNCHECKABLE
    assert "proj-1_2_0" in f.observed
    assert "--ref" in f.observed


def test_wrong_directory_stays_contradicted(repo):
    """The reporter names a real file under a directory it never lived in.
    This is the finding the tool exists to surface; it must survive."""
    f = check_path(Tree(str(repo)), claim("include/sys.c"))
    assert f.verdict == CONTRADICTED
    assert "the name is real but the location in the report is not" in f.observed


def test_wrong_directory_note_points_at_the_real_location(repo):
    f = check_path(Tree(str(repo)), claim("include/sys.c"))
    assert "old/sys.c" in f.observed or "new/sys.c" in f.observed


def test_fabricated_path_stays_contradicted_with_no_history(repo):
    f = check_path(Tree(str(repo)), claim("lib/never_existed.c"))
    assert f.verdict == CONTRADICTED
    assert "IS present at" not in f.observed


def test_deleted_file_that_never_moved_is_downgraded(repo):
    """only_here.h was deleted outright. A report about it is stale, not fake."""
    f = check_path(Tree(str(repo)), claim("old/only_here.h"))
    assert f.verdict == UNCHECKABLE
    assert "IS present at" in f.observed


def test_current_path_is_consistent(repo):
    f = check_path(Tree(str(repo)), claim("new/sys.c"))
    assert f.verdict not in (CONTRADICTED,)
    assert "present at" in f.observed


def test_probe_respects_the_history_budget(repo):
    t = Tree(str(repo))
    t._history_budget = 0
    note, downgrade = t.path_history_note("old/sys.c")
    assert note == "" and downgrade is False


# --- snippet_present must never assert the tree disagrees ------------------

def test_absent_snippet_is_uncheckable_not_contradicted(repo):
    """A quoted line that is absent proves nothing: reporters paste their own
    PoC code, build steps and output. Measured on 557 curl reports, this check
    was the sole contradiction on 19/126 confirmed vulnerabilities against
    5/49 archived slop -- far more false alarms than detections."""
    from slopcheck.checks import check_snippet
    from slopcheck.claims import Claim
    f = check_snippet(Tree(str(repo)),
                      Claim("snippet", "mkdir c:\\usr\\local\\ssl_and_more_padding\n", "ctx"))
    assert f.verdict == UNCHECKABLE
    assert "weak evidence" in f.observed


def test_present_snippet_is_still_consistent(repo):
    from slopcheck.checks import check_snippet, CONSISTENT
    from slopcheck.claims import Claim
    f = check_snippet(Tree(str(repo)),
                      Claim("snippet",
                            "int parse_header_field(const char *buf, size_t len){return 1;}\n",
                            "ctx"))
    assert f.verdict == CONSISTENT
    assert "found at" in f.observed
