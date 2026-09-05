"""Regression tests for release-tag selection.

recent_tags() is the entire evidence base for the stale-ref downgrade, which
is the mechanism that stops slopcheck emitting false CONTRADICTED on a genuine
report about an older release. Every bug in this function is silent: the
downgrade just quietly stops working, and the tool starts confidently
contradicting honest reporters.

Three real defects are pinned here. All three shipped.
"""
import subprocess
import pytest

from slopcheck.checks import Tree


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path):
    """A repo whose tag layout mirrors curl's: releases, RCs, and a fork variant."""
    r = tmp_path / "proj"
    r.mkdir()
    git(r, "init", "-q")
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")

    def commit(msg, body):
        (r / "src.c").write_text(body)
        git(r, "add", "-A")
        git(r, "commit", "-q", "-m", msg)

    # old_api() exists early, then is deleted -- the shape of the real case
    commit("v1", "int old_api(void) { return 1; }\n")
    git(r, "tag", "proj-8_11_1")
    commit("v2", "int old_api(void) { return 2; }\n")
    git(r, "tag", "proj-8_12_0")
    commit("remove old_api", "int new_api(void) { return 3; }\n")
    for t in ["proj-8_13_0", "proj-8_14_0", "proj-8_15_0", "proj-8_16_0",
              "proj-8_17_0", "proj-8_18_0"]:
        git(r, "tag", t)
    # noise the selector must reject
    for t in ["rc-8_18_0-1", "rc-8_18_0-2", "rc-8_18_0-3",
              "tiny-proj-8_4_0", "proj-8_19_0-beta"]:
        git(r, "tag", t)
    return r


def test_returns_more_than_two_tags(repo):
    """Defect: dedupe key rstrip('0123456789_-.') collapsed every tag to one
    family, so the loop stopped at 2 and probed half the claimed window."""
    assert len(Tree(str(repo)).recent_tags()) >= 6


def test_excludes_release_candidates(repo):
    """Defect: the newest tags by date were three RCs of a single release --
    one point in history counted four times."""
    tags = Tree(str(repo)).recent_tags()
    assert not [t for t in tags if "rc" in t.lower() or "beta" in t.lower()]


def test_excludes_fork_variants(repo):
    """Defect: curl publishes tiny-curl-*, a cut-down embedded build. Treating
    it as a release found a deleted symbol 'still present' and produced a false
    clean bill of health on a genuine report."""
    assert "tiny-proj-8_4_0" not in Tree(str(repo)).recent_tags()


def test_tags_are_newest_first_and_distinct(repo):
    tags = Tree(str(repo)).recent_tags()
    assert tags[0] == "proj-8_18_0"
    assert len(tags) == len(set(tags))


def test_window_reaches_back_far_enough_to_rescue_a_stale_symbol(repo):
    """The end-to-end property all of the above exist to protect."""
    t = Tree(str(repo), "proj-8_18_0")
    assert not t.grep_word("old_api")          # genuinely gone at this ref
    note = t.history_note("old_api")
    assert "proj-8_12_0" in note
    assert "--ref" in note                      # tells the user what to do


def test_no_note_for_a_symbol_that_never_existed(repo):
    """The downgrade must not fire for genuinely fabricated identifiers."""
    assert Tree(str(repo), "proj-8_18_0").history_note("Curl_totally_invented") == ""


def test_partial_clone_disables_history_probing(repo, monkeypatch):
    """On a blobless clone each probe refetches blobs; the tool must not hang."""
    t = Tree(str(repo), "proj-8_18_0")
    t.partial = True
    t._history_budget = 0
    assert t.history_note("old_api") == ""


def test_repo_with_no_parseable_tags_is_safe(tmp_path):
    r = tmp_path / "bare"
    r.mkdir()
    git(r, "init", "-q")
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    (r / "a.txt").write_text("x")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "init")
    git(r, "tag", "nightly")
    assert Tree(str(r)).recent_tags() == []
