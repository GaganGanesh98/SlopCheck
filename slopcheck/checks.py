"""Check extracted claims against a git working tree at a given ref.

Every check is read-only. Nothing is built, nothing is executed, no network is
touched. That is deliberate: this layer must be safe to run on a report from a
stranger, and fast enough to run on every submission.

Verdict vocabulary -- there are only three, and none of them is "slop":

  CONTRADICTED  the tree positively disagrees with the claim
                (file absent, line past EOF, symbol nowhere in the tree)
  CONSISTENT    the tree agrees; this is NOT evidence the bug is real
  UNCHECKABLE   we could not test it here (needs execution, or the claim is
                too vague to bind to anything)
"""
from __future__ import annotations

import re
import shutil
import subprocess
import threading
from dataclasses import dataclass, asdict

from .claims import Claim

CONTRADICTED = "CONTRADICTED"
CONSISTENT = "CONSISTENT"
UNCHECKABLE = "UNCHECKABLE"


@dataclass
class Finding:
    claim_kind: str
    claim_value: str
    check: str
    verdict: str
    observed: str
    context: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class RepoCache:
    """Git facts that depend only on (repo, ref), safe to share across Trees.

    A Tree's caches answer questions about the repository -- which files exist
    at a ref, what a blob contains, which tags there are, where a word occurs.
    None of that varies by report, so scoring a corpus with one Tree per report
    re-derives all of it once per report. On 557 curl reports that was ~10,000
    git subprocesses, dominated by re-listing the same trees.

    What must NOT be shared is `_history_budget`: that is per-report rate
    limiting, not data, and it stays on the Tree.

    Values are deterministic, so the compute runs outside the lock. A race
    duplicates work but cannot produce a wrong answer, and holding a lock
    across a git subprocess would serialise every worker.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._d: dict = {}

    def get(self, key, compute):
        try:
            return self._d[key]
        except KeyError:
            pass
        value = compute()
        with self._lock:
            return self._d.setdefault(key, value)

    def has(self, key) -> bool:
        return key in self._d

    def put(self, key, value) -> None:
        with self._lock:
            self._d.setdefault(key, value)

    def __len__(self) -> int:
        return len(self._d)


class Tree:
    """Read-only view of a git repository at one ref."""

    def __init__(self, repo: str, ref: str = "HEAD", cache: "RepoCache | None" = None):
        self.repo = repo
        self.ref = ref
        # Default is a private cache, so a lone Tree behaves exactly as before.
        # Pass a shared RepoCache to score many reports against one repository.
        self.cache = cache if cache is not None else RepoCache()
        self.has_rg = shutil.which("rg") is not None
        # A partial (blobless/treeless) clone makes cross-ref grep pathological:
        # every probe lazily refetches blobs over the network. Detect it once
        # and disable history probing rather than appearing to hang.
        self.partial = self._is_partial()
        # Per-report, never shared: this is rate limiting, not data.
        self._history_budget = 0 if self.partial else 12

    def _is_partial(self) -> bool:
        def probe() -> bool:
            p = self._git("config", "--get", "remote.origin.promisor")
            if p.stdout.strip() == "true":
                return True
            p = self._git("config", "--get", "remote.origin.partialclonefilter")
            return bool(p.stdout.strip())
        return self.cache.get(("partial", self.repo), probe)

    def _git(self, *args: str, check: bool = False) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "-C", self.repo, *args],
            capture_output=True, text=True, check=check, errors="replace",
        )

    def resolve_ref(self) -> str | None:
        p = self._git("rev-parse", "--verify", f"{self.ref}^{{commit}}")
        return p.stdout.strip() if p.returncode == 0 else None

    @property
    def files(self) -> set[str]:
        return self._ref_index(self.ref)[0]

    def find_paths_ending(self, path: str) -> list[str]:
        """Paths in the tree whose tail matches, e.g. 'os400sys.c'."""
        return sorted(self._ref_index(self.ref)[1].get(path.split("/")[-1], []))

    def basenames(self) -> set[str]:
        """Every file basename at this ref. Lets the claim extractor tell a
        real path:line reference from an arbitrary colon-separated token."""
        return set(self._ref_index(self.ref)[1])

    def resolve_path(self, path: str) -> str | None:
        """Bind a reported path to a real one.

        Stack traces carry the reporter's build directory --
        /tmp/repro/curl/lib/multi.c, /root/curl/build-afl/src/../../src/... --
        and valgrind prints bare basenames. Neither is a claim that the project
        ships that path; both name a file that is really there.
        """
        if path in self.files:
            return path
        cands = self.find_paths_ending(path)
        if len(cands) == 1:
            return cands[0]
        suffix = [c for c in cands if path.endswith(c)]
        return suffix[0] if len(suffix) == 1 else None

    def blob(self, path: str) -> str | None:
        def read():
            p = self._git("show", f"{self.ref}:{path}")
            return p.stdout if p.returncode == 0 else None
        return self.cache.get(("blob", self.repo, self.ref, path), read)

    def line_count(self, path: str) -> int | None:
        b = self.blob(path)
        return None if b is None else b.count("\n") + 1

    def grep_word(self, word: str) -> list[str]:
        """Whole-word search across the tree. Returns 'path:line' hits."""
        def search():
            p = self._git("grep", "-n", "-w", "-F", "--", word, self.ref)
            if p.returncode not in (0, 1):
                return []
            hits = []
            for ln in p.stdout.splitlines()[:200]:
                # format: <ref>:<path>:<lineno>:<text>
                parts = ln.split(":", 3)
                if len(parts) >= 3:
                    hits.append(f"{parts[1]}:{parts[2]}")
            return hits
        return self.cache.get(("grepw", self.repo, self.ref, word), search)

    def grep_fixed(self, needle: str) -> list[str]:
        def search():
            p = self._git("grep", "-n", "-F", "--", needle, self.ref)
            if p.returncode not in (0, 1):
                return []
            out = []
            for ln in p.stdout.splitlines()[:50]:
                parts = ln.split(":", 3)
                if len(parts) >= 3:
                    out.append(f"{parts[1]}:{parts[2]}")
            return out
        return self.cache.get(("grepf", self.repo, self.ref, needle), search)

    # One `git grep` costs ~60ms on a tree the size of curl's, and a corpus run
    # spent 93% of its wall time in them. `git grep -o` prints the matched text
    # itself, so a single call carrying many -e patterns can be partitioned back
    # into exact per-needle answers -- no heuristic attribution, same results.
    _BATCH_MAX = 200        # patterns per call
    _BATCH_BYTES = 60000    # keep well under ARG_MAX

    def _batches(self, needles: list[str]):
        cur: list[str] = []
        size = 0
        for w in needles:
            if cur and (len(cur) >= self._BATCH_MAX
                        or size + len(w) > self._BATCH_BYTES):
                yield cur
                cur, size = [], 0
            cur.append(w)
            size += len(w) + 4
        if cur:
            yield cur

    def _grep_located(self, needles: list[str], word: bool, cap: int,
                      kind: str) -> None:
        """Fill the cache with path:line hits for each needle, in few calls."""
        key = lambda w: (kind, self.repo, self.ref, w)
        todo = [w for w in dict.fromkeys(needles) if not self.cache.has(key(w))]
        for group in self._batches(todo):
            hits: dict[str, list[str]] = {w: [] for w in group}
            args = ["grep", "-n", "-o", "-F"] + (["-w"] if word else [])
            for w in group:
                args += ["-e", w]
            p = self._git(*args, self.ref)
            if p.returncode in (0, 1):
                for ln in p.stdout.splitlines():
                    # <ref>:<path>:<lineno>:<matched text>
                    parts = ln.split(":", 3)
                    if len(parts) < 4:
                        continue
                    bucket = hits.get(parts[3])
                    if bucket is None:
                        continue
                    loc = f"{parts[1]}:{parts[2]}"
                    # -o emits one line per occurrence; the un-batched code saw
                    # one line per matching LINE, so collapse repeats.
                    if not bucket or bucket[-1] != loc:
                        bucket.append(loc)
            for w in group:
                self.cache.put(key(w), hits[w][:cap])

    def prefetch_words(self, words: list[str]) -> None:
        self._grep_located(words, word=True, cap=200, kind="grepw")

    def prefetch_fixed(self, needles: list[str]) -> None:
        self._grep_located(needles, word=False, cap=50, kind="grepf")

    def prefetch_words_in_ref(self, words: list[str], ref: str) -> None:
        """Presence-only probe across one tag, batched. -h drops the filename,
        leaving just the matched identifiers."""
        key = lambda w: ("wordref", self.repo, ref, w)
        todo = [w for w in dict.fromkeys(words) if not self.cache.has(key(w))]
        for group in self._batches(todo):
            args = ["grep", "-h", "-o", "-w", "-F"]
            for w in group:
                args += ["-e", w]
            p = self._git(*args, ref)
            found = set(p.stdout.split()) if p.returncode in (0, 1) else set()
            for w in group:
                self.cache.put(key(w), w in found)

    def commit_exists(self, sha: str) -> bool:
        return self.cache.get(
            ("commit", self.repo, sha),
            lambda: self._git("cat-file", "-e", f"{sha}^{{commit}}").returncode == 0)

    def tags(self) -> list[str]:
        return self.cache.get(
            ("tags", self.repo),
            lambda: (lambda p: p.stdout.split() if p.returncode == 0 else [])(self._git("tag")))

    def recent_tags(self, n: int = 14) -> list[str]:
        """The project's N most recent RELEASE tags, newest first.

        Getting this right matters more than it looks: this list is the entire
        evidence base for the stale-ref downgrade, and a bad list silently
        turns that safety net off. Three distinct ways it goes wrong, all of
        which bit this code:

          1. Collapsing every tag to one "family" and stopping after two.
          2. Taking the newest tags literally, which are release candidates of
             a single release -- one point in history wearing four hats.
          3. Letting fork/variant tags in. curl publishes `tiny-curl-*`, a
             cut-down embedded build. It is not a curl release, and treating
             it as one produced a false "symbol still exists" and with it a
             false clean bill of health on a genuine report.

        So: drop pre-release tags, group by prefix, keep only the dominant
        prefix (the mainline series), and walk back N distinct versions.
        """
        return self.cache.get(("recent_tags", self.repo, n),
                              lambda: self._compute_recent_tags(n))

    def _compute_recent_tags(self, n: int) -> list[str]:
        p = self._git("tag", "--sort=-creatordate")
        if p.returncode != 0:
            return []

        prerelease = re.compile(r"(?i)(?:^|[-_.])(rc|alpha|beta|pre|dev|snapshot|test)")
        verpat = re.compile(r"(\d+)[._](\d+)(?:[._](\d+))?")

        parsed: list[tuple[str, tuple[int, ...], str]] = []
        for t in p.stdout.split():
            if prerelease.search(t):
                continue
            m = verpat.search(t)
            if not m:
                continue
            prefix = t[: m.start()]
            ver = tuple(int(g) for g in m.groups() if g is not None)
            parsed.append((prefix, ver, t))
        if not parsed:
            return []

        counts: dict[str, int] = {}
        for prefix, _, _ in parsed:
            counts[prefix] = counts.get(prefix, 0) + 1
        mainline = max(counts, key=lambda k: (counts[k], -len(k)))

        series = sorted((x for x in parsed if x[0] == mainline),
                        key=lambda x: x[1], reverse=True)
        out, seen_ver = [], set()
        for _, ver, tag in series:
            if ver in seen_ver:
                continue
            seen_ver.add(ver)
            out.append(tag)
            if len(out) >= n:
                break
        return out

    def word_in_ref(self, word: str, ref: str) -> bool:
        return self.cache.get(
            ("wordref", self.repo, ref, word),
            lambda: self._git("grep", "-q", "-w", "-F", "--", word, ref).returncode == 0)

    def path_in_ref(self, path: str, ref: str) -> bool:
        return path in self._ref_index(ref)[0]

    def _ref_index(self, ref: str) -> tuple[set[str], dict[str, list[str]]]:
        """One `ls-tree` per ref, cached: (all paths, basename -> paths).

        Without this the path probe re-listed the whole tree once per tag per
        claim -- 14 ls-tree calls for every path claim that missed, measured at
        ~0.5s each time. Now it is at most 14 for the entire run, and both the
        exact-path and basename questions are answered from memory.
        """
        def build():
            p = self._git("ls-tree", "-r", "--name-only", ref)
            listed = p.stdout.splitlines() if p.returncode == 0 else []
            by_tail: dict[str, list[str]] = {}
            # Build from git's own ordering, NOT from the set: iterating a set
            # of strings varies between processes under hash randomisation, and
            # path_history_note reports elsewhere[0], so that made the observed
            # text non-reproducible run to run.
            for f in listed:
                by_tail.setdefault(f.rsplit("/", 1)[-1], []).append(f)
            return (set(listed), by_tail)
        return self.cache.get(("tree", self.repo, ref), build)

    def files_ending_in_ref(self, tail: str, ref: str) -> list[str]:
        return self._ref_index(ref)[1].get(tail, [])

    def line_count_in_ref(self, path: str, ref: str) -> int | None:
        def read():
            p = self._git("show", f"{ref}:{path}")
            return p.stdout.count("\n") + 1 if p.returncode == 0 else None
        return self.cache.get(("lines", self.repo, ref, path), read)

    def line_history_note(self, path: str, lineno: int) -> tuple[str, bool]:
        """History context for a line claim. Returns (note, should_downgrade).

        The symbol and path axes have had this since early on; the line axis
        went without it, and that asymmetry became the largest single source of
        false contradictions once the extraction bugs were gone. Files shrink:
        lib/url.c has gone from 4,086 lines to 2,600, so every report that
        correctly cited a line in the old file is contradicted at HEAD.

        A file long enough at a recent release is a stale ref, not a fabricated
        line number.
        """
        if self._history_budget <= 0:
            return "", False
        self._history_budget -= 1
        tail = path.rsplit("/", 1)[-1]
        for t in self.recent_tags():
            at = path if self.path_in_ref(path, t) else None
            if at is None:
                elsewhere = self.files_ending_in_ref(tail, t)
                at = elsewhere[0] if elsewhere else None
            if at is None:
                continue
            n = self.line_count_in_ref(at, t)
            if n is not None and lineno <= n:
                return (f" — but {at} had {n} lines at {t}, so the report may "
                        f"describe an older release; re-run with --ref set to "
                        f"the version the reporter named"), True
        return "", False

    def path_history_note(self, path: str) -> tuple[str, bool]:
        """History context for a path claim. Returns (note, should_downgrade).

        Two different questions hide inside 'this file is missing', and they
        deserve different answers:

          (a) Did THIS EXACT path exist at an older release?  If so the
              reporter is describing a real file that has since moved or gone,
              which is a stale-ref problem, not a fabrication -> downgrade.

          (b) Did a file with this BASENAME exist somewhere else?  That is
              useful context, but it must NOT downgrade. A reporter who writes
              `include/tool_binmode.h` when the file lived at
              `src/tool_binmode.h` cited the wrong location, and saying so is
              the single most useful thing this tool can tell a maintainer.
              Suppressing it would throw away a correct finding.
        """
        if self._history_budget <= 0:
            return "", False
        self._history_budget -= 1
        tags = self.recent_tags()

        exact = [t for t in tags if self.path_in_ref(path, t)]
        if exact:
            return (" — but it IS present at " + ", ".join(exact[:3])
                    + "; the report may describe an older release, so re-run "
                      "with --ref set to the version the reporter named"), True

        tail = path.split("/")[-1]
        for t in tags:
            elsewhere = self.files_ending_in_ref(tail, t)
            if elsewhere:
                return (f" — though a file of that name existed at "
                        f"{elsewhere[0]} in {t}, so the name is real but the "
                        f"location in the report is not"), False
        return "", False

    def history_note(self, word: str, is_path: bool = False) -> str:
        """Cheap 'when did this exist' probe: grep a handful of release tags.

        Deliberately avoids `git log -S`, which is pathologically slow on
        blobless/partial clones -- the kind most people will make.
        """
        if self._history_budget <= 0:
            return ""
        self._history_budget -= 1
        found = []
        for tag in self.recent_tags():
            hit = (self.path_in_ref(word, tag) if is_path
                   else self.word_in_ref(word, tag))
            if hit:
                found.append(tag)
                # The note names at most three, and tags are newest-first, so
                # the remaining greps cannot change the output.
                if len(found) >= 3:
                    break
        if not found:
            return ""
        return (" — but it IS present at " + ", ".join(found[:3])
                + "; the report may describe an older release, so re-run with "
                  "--ref set to the version the reporter named")


# --- individual checks ----------------------------------------------------

def check_path(t: Tree, c: Claim) -> Finding:
    if c.value in t.files:
        return Finding(c.kind, c.value, "file_exists", CONSISTENT,
                       f"present at {t.ref}", c.context)
    note, downgrade = t.path_history_note(c.value)
    near = t.find_paths_ending(c.value)
    if near:
        # Three different things hide behind "a file of that name is elsewhere",
        # and only the third is a disagreement.
        #
        # The reported path ENDS WITH a real one: a build-directory prefix in
        # front of a file that is present (/tmp/repro/curl/lib/multi.c). The
        # tree agrees; the prefix is local to the reporter's machine.
        exact = [p for p in near if c.value.endswith(p)]
        if exact:
            return Finding(c.kind, c.value, "file_exists", CONSISTENT,
                           f"present at {exact[0]}; the reported path carries a "
                           f"build-directory prefix", c.context)
        # A bare basename, as valgrind and gdb print them (ftp.c). No directory
        # was asserted, so there is no directory to disagree with.
        if "/" not in c.value:
            return Finding(c.kind, c.value, "file_exists", CONSISTENT,
                           f"present at {', '.join(near[:4])}; the report names "
                           f"the file without a directory", c.context)
        # A directory WAS asserted, and the file has never been in it. This is
        # the finding the tool exists to surface, and it stays.
        return Finding(
            c.kind, c.value, "file_exists", UNCHECKABLE if downgrade else CONTRADICTED,
            f"no such path at {t.ref}; a file with that name exists elsewhere: "
            + ", ".join(near[:4]) + note,
            c.context,
        )
    if "/" not in c.value:
        # A bare filename with no match is usually the reporter's own artifact
        # (poc.c, rogue_server.py), not a claim about the project. Saying
        # "CONTRADICTED" there would be wrong and would train maintainers to
        # ignore the tool.
        return Finding(c.kind, c.value, "file_exists", UNCHECKABLE,
                       "bare filename with no match in the tree; likely the reporter's "
                       "own file rather than a claim about this project" + note,
                       c.context)
    return Finding(c.kind, c.value, "file_exists",
                   UNCHECKABLE if downgrade else CONTRADICTED,
                   f"no such path at {t.ref}, and no file of that name anywhere "
                   f"in the tree" + note,
                   c.context)


def check_line(t: Tree, c: Claim) -> Finding:
    path = c.extra.get("path")
    if not path:
        return Finding(c.kind, c.value, "line_in_range", UNCHECKABLE,
                       "line number not bound to a file in the report", c.context)
    resolved = t.resolve_path(path)
    if resolved is None:
        # Not reading the file is a statement about this tool's reach, not
        # about the tree. 602 of 625 contradictions in the curl corpus were
        # this, and every one of them was wrong -- the same semantic point
        # already settled for snippet_present.
        return Finding(c.kind, c.value, "line_in_range", UNCHECKABLE,
                       f"cannot bind {path} to a file in the tree at {t.ref}, "
                       f"so the line number cannot be checked", c.context)
    n = t.line_count(resolved)
    if n is None:
        return Finding(c.kind, c.value, "line_in_range", UNCHECKABLE,
                       f"cannot read {resolved} at {t.ref}", c.context)
    via = "" if resolved == path else f" (reported as {path})"
    if int(c.value) > n:
        note, downgrade = t.line_history_note(resolved, int(c.value))
        return Finding(c.kind, c.value, "line_in_range",
                       UNCHECKABLE if downgrade else CONTRADICTED,
                       f"{resolved} is {n} lines long at {t.ref}{via}; "
                       f"line {c.value} does not exist" + note, c.context)
    return Finding(c.kind, c.value, "line_in_range", CONSISTENT,
                   f"{resolved} has {n} lines at {t.ref}{via}", c.context)


_HEXISH = re.compile(r"[0-9a-f]{7,40}")


def check_symbol(t: Tree, c: Claim) -> Finding:
    hits = t.grep_word(c.value)
    if not hits:
        # A short hex run that resolves is an object the reporter cited
        # correctly, not an identifier they invented. The extractor now
        # declines to emit these; this is the second line of defence, and it
        # answers rather than staying silent.
        if _HEXISH.fullmatch(c.value) and t.commit_exists(c.value):
            return Finding(c.kind, c.value, "symbol_exists", CONSISTENT,
                           "not an identifier: this is a commit in this "
                           "repository", c.context)
        note = t.history_note(c.value)
        # If it exists at a recent release, this is a stale-ref problem, not a
        # fabricated symbol. Downgrading is the honest call.
        verdict = UNCHECKABLE if note else CONTRADICTED
        return Finding(c.kind, c.value, "symbol_exists", verdict,
                       f"identifier appears nowhere in the tree at {t.ref} "
                       f"(whole-word search)" + note, c.context)
    where = ", ".join(hits[:3]) + (f" (+{len(hits)-3} more)" if len(hits) > 3 else "")
    return Finding(c.kind, c.value, "symbol_exists", CONSISTENT,
                   f"{len(hits)} occurrence(s): {where}", c.context)


def check_commit(t: Tree, c: Claim) -> Finding:
    if t.commit_exists(c.value):
        return Finding(c.kind, c.value, "commit_exists", CONSISTENT,
                       "commit is in this repository", c.context)
    return Finding(c.kind, c.value, "commit_exists", CONTRADICTED,
                   "no such commit in this repository", c.context)


def _snippet_needle(body: str) -> str | None:
    """The line a snippet is judged by. Shared with the prefetch pass so the
    batched lookup and the check can never disagree about what was searched."""
    cands = [l for l in (x.strip() for x in body.splitlines())
             if len(l) > 25 and not l.startswith(("#", "//", "*", "$", ">"))]
    return max(cands, key=len) if cands else None


def check_snippet(t: Tree, c: Claim) -> Finding:
    """Does a distinctive line of the quoted code appear in the tree?

    Reports frequently quote a 'snippet from the source' that was actually
    written by the reporter. We test the longest non-trivial line.
    """
    needle = _snippet_needle(c.value)
    if needle is None:
        return Finding(c.kind, c.value[:60], "snippet_present", UNCHECKABLE,
                       "no distinctive line to search for", c.context)
    hits = t.grep_fixed(needle)
    short = (needle[:70] + "...") if len(needle) > 70 else needle
    if hits:
        return Finding(c.kind, short, "snippet_present", CONSISTENT,
                       f"found at {hits[0]}", c.context)
    # UNCHECKABLE, not CONTRADICTED, and this is a semantic point rather than a
    # tuning choice. CONTRADICTED means the tree positively disagrees. A quoted
    # line that is absent proves nothing of the kind: reporters legitimately
    # paste their own proof-of-concept code, build steps, pseudo-code, patches,
    # terminal output and reformatted excerpts. The tree does not disagree with
    # those -- it simply has nothing to say about them.
    #
    # Measured on 557 curl reports: snippet_present was the SOLE contradiction
    # on 19 of 126 confirmed vulnerabilities against only 5 of 49 archived slop
    # reports -- close to 4:1 against. Demoting it drops the false-contradiction
    # rate on genuine reports from 73.0% to 57.9% while WIDENING the gap to slop
    # from +10.7 to +15.5 points. Absolute catch rate was never the goal;
    # separation is, and separation improves.
    return Finding(c.kind, short, "snippet_present", UNCHECKABLE,
                   f"this line does not appear in the tree at {t.ref}; that is "
                   f"weak evidence either way, since reporters routinely quote "
                   f"their own code, build steps or output rather than project "
                   f"source", c.context)


def check_version(t: Tree, c: Claim) -> Finding:
    tags = t.tags()
    norm = c.value.replace(".", "_")
    matches = [x for x in tags if norm in x or c.value in x]
    if matches:
        return Finding(c.kind, c.value, "version_tagged", CONSISTENT,
                       f"matching tag(s): {', '.join(matches[:3])}", c.context)
    return Finding(c.kind, c.value, "version_tagged", UNCHECKABLE,
                   "no matching git tag; the project may not tag this way", c.context)


CHECKS = {
    "path": check_path,
    "line": check_line,
    "symbol": check_symbol,
    "commit": check_commit,
    "snippet": check_snippet,
    "version": check_version,
    "cve": None,   # needs an advisory feed; deliberately out of scope for v1
}


def _prefetch(tree: Tree, claims: list[Claim], max_symbols: int) -> None:
    """Resolve every grep this report needs in a handful of batched calls.

    Purely a cache warm-up: each check still asks the same question and gets
    the same answer, it just finds it already computed. Verdicts are unchanged
    by construction, and that is verified against the full 557-report corpus.
    """
    symbols, snippets, seen = [], [], 0
    for c in claims:
        if c.kind == "symbol":
            seen += 1
            if seen <= max_symbols:
                symbols.append(c.value)
        elif c.kind == "snippet":
            n = _snippet_needle(c.value)
            if n:
                snippets.append(n)
    tree.prefetch_words(symbols)
    tree.prefetch_fixed(snippets)

    # Symbols absent at this ref trigger the history probe, which otherwise
    # greps each release tag once PER SYMBOL. Batched it is one call per tag
    # for the whole report, regardless of how many symbols are missing.
    if tree._history_budget > 0:
        missing = [w for w in dict.fromkeys(symbols) if not tree.grep_word(w)]
        if missing:
            for tag in tree.recent_tags():
                tree.prefetch_words_in_ref(missing, tag)


def run(tree: Tree, claims: list[Claim], max_symbols: int = 40) -> list[Finding]:
    _prefetch(tree, claims, max_symbols)
    findings: list[Finding] = []
    sym_seen = 0
    for c in claims:
        fn = CHECKS.get(c.kind)
        if fn is None:
            findings.append(Finding(c.kind, c.value, "not_implemented", UNCHECKABLE,
                                    "no check for this claim type in v1", c.context))
            continue
        if c.kind == "symbol":
            sym_seen += 1
            if sym_seen > max_symbols:
                continue
        findings.append(fn(tree, c))
    return findings
