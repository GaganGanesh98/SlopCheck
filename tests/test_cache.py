"""Tests for the shared repository cache and the batched grep path.

Two properties matter here and they pull against each other:

  - Facts about the repository (file lists, blobs, tags, grep hits) are the
    same for every report, so sharing them is correct and is the difference
    between 20,295 and 4,160 git subprocesses over a 557-report corpus.
  - `_history_budget` is per-report rate limiting, NOT data. Sharing it would
    let one report exhaust the probe for the next.

The batched path must also be indistinguishable from the unbatched one. It is
an optimisation; if it changes a single verdict it is a bug.
"""
import subprocess
import pytest

from slopcheck.checks import Tree, RepoCache
from slopcheck.claims import Claim
from slopcheck import checks


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


@pytest.fixture(scope="module")
def repo(tmp_path_factory):
    r = tmp_path_factory.mktemp("cached")
    (r / "lib").mkdir()
    (r / "docs").mkdir()
    # same basename in two directories: the case that exposed the ordering bug
    (r / "lib" / "urlapi.c").write_text("int Curl_url_get(void){return 1;}\n")
    (r / "docs" / "urlapi.c").write_text("/* example */\nint demo(void){return 0;}\n")
    (r / "lib" / "gone.c").write_text("int Curl_removed_helper(void){return 2;}\n")
    git(r, "init", "-q")
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "v1")
    for t in ("proj-1_0_0", "proj-1_1_0"):
        git(r, "tag", "-a", "-m", "r", t)
    git(r, "rm", "-q", "lib/gone.c")
    git(r, "commit", "-q", "-m", "drop helper")
    git(r, "tag", "-a", "-m", "r", "proj-1_2_0")
    return r


def test_basename_order_is_deterministic(repo):
    """Regression: _ref_index built its basename map by iterating a set, so the
    same call returned a different order in each process under hash
    randomisation -- and path_history_note reports elsewhere[0]."""
    listed = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "proj-1_2_0"],
        capture_output=True, text=True).stdout.splitlines()
    expected = [f for f in listed if f.rsplit("/", 1)[-1] == "urlapi.c"]
    for _ in range(5):
        got = Tree(str(repo), "proj-1_2_0").files_ending_in_ref("urlapi.c", "proj-1_2_0")
        assert got == expected, "basename order must follow git's own listing"


def test_shared_cache_gives_identical_findings(repo):
    """A shared cache is an optimisation; it must not change a single verdict."""
    claims = [Claim("path", "lib/urlapi.c"), Claim("path", "nope/urlapi.c"),
              Claim("symbol", "Curl_url_get"), Claim("symbol", "Curl_removed_helper"),
              Claim("symbol", "Curl_never_existed"),
              Claim("line", "1", extra={"path": "lib/urlapi.c"})]
    private = [(f.claim_value, f.verdict, f.observed)
               for f in checks.run(Tree(str(repo), "proj-1_2_0"), claims)]
    shared_cache = RepoCache()
    shared = [(f.claim_value, f.verdict, f.observed)
              for f in checks.run(Tree(str(repo), "proj-1_2_0", cache=shared_cache), claims)]
    again = [(f.claim_value, f.verdict, f.observed)
             for f in checks.run(Tree(str(repo), "proj-1_2_0", cache=shared_cache), claims)]
    assert private == shared
    assert shared == again, "a warm cache must not change the second report's answers"


def test_history_budget_is_not_shared(repo):
    """Budget is per-report rate limiting; sharing it would let one report
    exhaust the history probe for every report after it."""
    cache = RepoCache()
    a = Tree(str(repo), "proj-1_2_0", cache=cache)
    a._history_budget = 0
    b = Tree(str(repo), "proj-1_2_0", cache=cache)
    assert b._history_budget > 0


def test_shared_cache_cuts_git_calls(repo):
    """The whole point: repository facts are derived once, not once per report."""
    claims = [Claim("symbol", "Curl_url_get"), Claim("path", "lib/urlapi.c")]
    calls = []
    orig = Tree._git

    def counted(self, *a, **k):
        calls.append(a[0] if a else "?")
        return orig(self, *a, **k)

    Tree._git = counted
    try:
        cache = RepoCache()
        checks.run(Tree(str(repo), "proj-1_2_0", cache=cache), claims)
        first = len(calls)
        calls.clear()
        checks.run(Tree(str(repo), "proj-1_2_0", cache=cache), claims)
        second = len(calls)
    finally:
        Tree._git = orig
    assert second < first, f"warm run made {second} calls, cold made {first}"


def test_batched_prefetch_matches_one_at_a_time(repo):
    """git grep -o names the matched pattern, so a batched call must partition
    back to exactly what a per-word call would have returned."""
    words = ["Curl_url_get", "demo", "Curl_never_existed", "Curl_removed_helper"]
    one_at_a_time = {}
    for w in words:
        t = Tree(str(repo), "proj-1_2_0")
        t.cache.put(("sentinel",), True)          # keep caches separate per word
        one_at_a_time[w] = t.grep_word(w)
    t = Tree(str(repo), "proj-1_2_0")
    t.prefetch_words(words)
    assert {w: t.grep_word(w) for w in words} == one_at_a_time


def test_batching_splits_oversized_groups(repo):
    t = Tree(str(repo), "proj-1_2_0")
    groups = list(t._batches([f"w{i}" for i in range(500)]))
    assert len(groups) > 1
    assert sum(len(g) for g in groups) == 500
    assert all(len(g) <= t._BATCH_MAX for g in groups)
