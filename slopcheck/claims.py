"""Extract checkable claims from the prose of a vulnerability report.

Design rule: we only extract things a source tree can CONTRADICT. Vague prose
("attacker-controlled input may lead to RCE") produces no claims, and that is
correct behaviour -- an unfalsifiable report should surface as "nothing to
check", not as a low score.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Iterator

SOURCE_EXT = (
    "c cc cpp cxx h hpp hh py java go rs js ts jsx tsx rb php cs swift kt "
    "m mm scala pl sh bash lua sql yaml yml toml"
).split()

# --- patterns -------------------------------------------------------------

_PATH = re.compile(
    r"(?<![\w/.-])((?:[\w.-]+/)*[\w.-]+\.(?:" + "|".join(SOURCE_EXT) + r"))(?![\w])"
)
# "line 741", "lines 741, 773 and 804", "at line 3555", "os400sys.c:741"
_LINE_WORD = re.compile(
    # "line 741" / "lines 741, 773, and 804" / "lines 12-19".
    # Separators can stack (", and "), so allow a run of them between numbers.
    r"\blines?\s+(\d{1,7}(?:[\s,&-]*(?:and|to|or)?[\s,&-]*\d{1,7})*)",
    re.I,
)
_PATH_LINE = re.compile(
    r"((?:[\w.-]+/)*[\w.-]+\.(?:" + "|".join(SOURCE_EXT) + r")):(\d{1,7})"
)
_INT = re.compile(r"\d{1,7}")

# Identifier immediately followed by "(" -- the common way reports name a
# function. No whitespace allowed: "Remote Code Execution (RCE)" is English
# prose, "strcpy(cp, cp2)" is a call. That single space is the whole signal.
_CALL = re.compile(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]{2,})\(")
# backticked or explicitly labelled symbols
_TICKED = re.compile(r"`([A-Za-z_][A-Za-z0-9_]{2,})(?:\(\))?`")
_LABELLED = re.compile(
    r"\b(?:function|method|symbol|routine|api)\s*[:\-]?\s*"
    r"(?:`|\*\*)?(?:static\s+|inline\s+)*(?:[\w*]+\s+)?"
    r"([A-Za-z_][A-Za-z0-9_]{2,})\(",
    re.I,
)

# An identifier that is plain English prose is not a code symbol. Require one
# code-shaped feature: an underscore, an internal capital, or a known project
# prefix. This is a recall/precision trade made deliberately towards precision:
# a missed symbol costs nothing, a false CONTRADICTED costs the tool its
# credibility with the maintainer reading it.
_CODE_SHAPED = re.compile(r"_|[a-z][A-Z]|^[a-z]+[0-9]")


def _looks_like_code(name: str) -> bool:
    return bool(_CODE_SHAPED.search(name)) or name.isupper()

_SHA = re.compile(r"(?<![\w])([0-9a-f]{7,40})(?![\w])")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
# Match the whole dotted run, then keep only 2- or 3-component ones. Anchoring
# on the full run is what keeps IP addresses out: the "127.0.0" inside
# 127.0.0.1 is not a version claim, and a \b-delimited pattern happily
# extracts it.
_VERSION = re.compile(r"(?<![\w.])(?:v(?=\d)|version\s+)?(\d+(?:\.\d+)+)(?![\w])", re.I)
_FENCE = re.compile(r"```[\w+-]*\n(.*?)```", re.S)

# Words that look like function calls but are noise.
_STOPWORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "printf", "sprintf",
    "the", "and", "not", "see", "e.g", "i.e", "etc", "fig", "note", "step",
    "https", "http", "www", "com", "org", "net", "png", "jpg",
}
# Standard-library names: their absence from a project tree proves nothing.
_STDLIB = {
    "strcpy", "strcat", "sprintf", "memcpy", "memmove", "malloc", "calloc",
    "realloc", "free", "strlen", "strncpy", "strncat", "snprintf", "gets",
    "scanf", "sscanf", "fopen", "fread", "fwrite", "fclose", "system", "exec",
    "open", "read", "write", "close", "printf", "puts", "exit", "abort",
    "alloca", "strdup", "atoi", "strtol", "memset", "assert",
}


@dataclass
class Claim:
    kind: str          # path | line | symbol | symbol_at | snippet | commit | cve | version
    value: str
    context: str = ""  # the sentence it came from, for the transcript
    extra: dict = field(default_factory=dict)

    def key(self) -> tuple:
        return (self.kind, self.value, tuple(sorted(self.extra.items())))

    def to_dict(self) -> dict:
        return asdict(self)


def _sentence_around(text: str, pos: int, width: int = 150) -> str:
    lo = max(0, pos - width // 2)
    hi = min(len(text), pos + width // 2)
    return " ".join(text[lo:hi].split())


def _expand_numbers(blob: str) -> list[str]:
    return _INT.findall(blob)


# --- who is asserting it --------------------------------------------------
#
# A vulnerability report is two documents in one: prose making claims ABOUT the
# project, and the reporter's own artifacts -- proof-of-concept source, server
# stubs, build scripts -- which make no claims about the project at all. Their
# identifiers are absent from the tree by construction, and flagging them
# produced 60% of every surviving contradiction across the curl corpus.
#
# The split is NOT "inside a fence" versus "outside". Stack traces live inside
# fences 4.5:1 over prose, and a frame naming a function and a file is the
# single highest-quality claim a report ever makes. What separates them is who
# is speaking: a frame, a diff header and a path:line are the reporter quoting
# the project, while the surrounding C and Python is the reporter quoting
# themselves.

# "#12 0x55cc37b1541c in state_performing /tmp/repro/curl/lib/multi.c:1915:12"
# "==5247==    by 0x48AF420: push_promise (http2.c:877)"
# "#8  0x00005555555eae21 in wc_statemach (conn=0x...) at ftp.c:3836"
_FRAME_LINE = re.compile(
    r"""^\s*(?:==\d+==\s*)?              # valgrind pid prefix
        (?: \#\d+\s                      # ASan / gdb frame number
          | (?:by|at)\s+0x[0-9a-fA-F]+   # valgrind frame
        )""",
    re.X,
)
# The function name in a frame: "in <name>" (ASan, gdb) or "0xADDR: <name>"
# (valgrind). These names are never followed directly by "(", so the ordinary
# _CALL pattern cannot see them.
_FRAME_SYM = re.compile(
    r"(?:\bin\s+|0x[0-9a-fA-F]+:\s*)([A-Za-z_][A-Za-z0-9_]{2,})")

# Diff headers name paths and line anchors. Deliberately NOT the "index
# cea88e668..ddfb65344" line: those are blob hashes, and reading them as commit
# references produced a contradiction on every single one in the corpus.
_DIFF_LINE = re.compile(r"^\s*(?:diff --git |--- |\+\+\+ |@@ )")

_BLANK = re.compile(r"[^\n]")


def _blank(s: str) -> str:
    """Same length, same line structure, no content -- so that positions in a
    masked stream still index into the original text for context."""
    return _BLANK.sub(" ", s)


def _partition(text: str, known_basenames: set[str] | None) -> tuple[str, str, str]:
    """Split the report into three position-preserving streams.

    prose  -- everything outside fenced blocks; extracted from as before.
    frames -- fenced lines that are stack frames; paths, lines AND symbols.
    refs   -- fenced diff headers and path:line references; paths and lines
              only, never symbols.
    """
    spans = [(m.start(), m.end()) for m in _FENCE.finditer(text)]
    if not spans:
        return text, _blank(text), _blank(text)

    prose = list(text)
    frames = list(_blank(text))
    refs = list(_blank(text))

    for a, b in spans:
        for ch in range(a, b):
            prose[ch] = " " if text[ch] != "\n" else "\n"
        pos = a
        for line in text[a:b].splitlines(keepends=True):
            stripped = line.rstrip("\n")
            # A frame yields its function name only when the frame itself
            # names a file in THIS tree. curl links OpenSSL, glibc, wolfSSL
            # and libssh2, and an ASan trace is mostly not curl frames:
            # "#0 in __asan_memcpy" and "in CRYPTO_zalloc .../crypto/mem.c"
            # are the sanitiser and the TLS library talking about themselves.
            if _FRAME_LINE.search(stripped) and _qualifying_ref(stripped, known_basenames):
                dest = frames
            elif _DIFF_LINE.search(stripped) or _qualifying_ref(stripped, known_basenames):
                dest = refs
            else:
                dest = None
            if dest is not None:
                for i, ch in enumerate(line):
                    dest[pos + i] = ch
            pos += len(line)

    return "".join(prose), "".join(frames), "".join(refs)


def _qualifying_ref(line: str, known_basenames: set[str] | None) -> bool:
    """A 'path:line' whose basename really is a file in the tree.

    Without a tree to consult we accept it: the checks downstream still have to
    agree, and over-extraction here costs recall in the transcript, not a false
    CONTRADICTED.
    """
    for m in _PATH_LINE.finditer(line):
        if known_basenames is None:
            return True
        if m.group(1).rsplit("/", 1)[-1] in known_basenames:
            return True
    return False


def _strip_diff_prefix(path: str) -> str:
    """`diff --git a/lib/hostip.c b/lib/hostip.c` names one file twice. The
    a/ and b/ are diff syntax; reading them as directories turns every patch
    in a report into a wrong-directory contradiction."""
    return path[2:] if path[:2] in ("a/", "b/") else path


def _is_hexish(name: str) -> bool:
    """An abbreviated object hash the reporter cited correctly. Every one of
    the 42 distinct hex 'symbols' in the curl corpus resolved to a real commit,
    and every one was reported as a nonexistent identifier."""
    return bool(re.fullmatch(r"[0-9a-f]{7,40}", name)) and not name.isdigit()


def extract(text: str, known_basenames: set[str] | None = None) -> list[Claim]:
    """Return de-duplicated claims, in a stable order.

    `known_basenames` -- the set of file basenames present in the target tree,
    when one is available. Used only to recognise a path:line reference inside
    a fenced block; extraction is otherwise independent of the tree.
    """
    out: list[Claim] = []
    seen: set[tuple] = set()

    def add(c: Claim) -> None:
        if c.key() not in seen:
            seen.add(c.key())
            out.append(c)

    prose, frames, refs = _partition(text, known_basenames)

    def ctx(pos: int) -> str:
        return _sentence_around(text, pos)

    # --- paths and line numbers: prose, frames and diff/ref lines ----------
    for stream in (prose, frames, refs):
        for m in _PATH_LINE.finditer(stream):
            path, line = _strip_diff_prefix(m.group(1)), m.group(2)
            add(Claim("path", path, ctx(m.start())))
            add(Claim("line", line, ctx(m.start()), {"path": path}))

        for m in _PATH.finditer(stream):
            add(Claim("path", _strip_diff_prefix(m.group(1)), ctx(m.start())))

        # bare "line N" attaches to the nearest preceding path IN THE SAME
        # stream, so a fenced frame cannot bind itself to a prose filename.
        for m in _LINE_WORD.finditer(stream):
            prior = [p for p in _PATH.finditer(stream[: m.start()])]
            path = prior[-1].group(1) if prior else ""
            for n in _expand_numbers(m.group(1)):
                add(Claim("line", n, ctx(m.start()),
                          {"path": path} if path else {}))

    # --- symbols: prose as before, plus the function names in stack frames --
    symbols: set[str] = set()

    def add_symbol(name: str, pos: int) -> None:
        low = name.lower()
        if low in _STOPWORDS or low in _STDLIB or name.isdigit():
            return
        if _is_hexish(name):
            return
        if not _looks_like_code(name):
            return
        if name in symbols:
            return
        symbols.add(name)
        add(Claim("symbol", name, ctx(pos)))

    for pat in (_LABELLED, _TICKED, _CALL):
        for m in pat.finditer(prose):
            add_symbol(m.group(1), m.start())
    for pat in (_FRAME_SYM, _LABELLED, _TICKED, _CALL):
        for m in pat.finditer(frames):
            add_symbol(m.group(1), m.start())

    # --- commits, CVEs, versions: prose only ------------------------------
    # Inside a fence these are thread ids in a debug log, ASan BuildIds and
    # blob hashes on a diff's index line -- never a commit the reporter named.
    for m in _SHA.finditer(prose):
        sha = m.group(1)
        if sha.isdigit():
            continue
        labelled = re.search(r"commit\s+$", text[: m.start()], re.I)
        if len(sha) >= 8 or labelled:
            add(Claim("commit", sha, ctx(m.start())))

    for m in _CVE.finditer(prose):
        add(Claim("cve", m.group(0).upper(), ctx(m.start())))

    for m in _VERSION.finditer(prose):
        if m.group(1).count(".") > 2:
            continue  # dotted quad or longer: an address, not a version
        add(Claim("version", m.group(1), ctx(m.start())))

    # Snippets come from the whole document: a fenced block is a snippet
    # regardless of who wrote it, and snippet_present never contradicts.
    for m in _FENCE.finditer(text):
        body = m.group(1).strip()
        if 20 < len(body) < 4000:
            add(Claim("snippet", body, "fenced code block"))

    return out


def summarise(claims: list[Claim]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for c in claims:
        counts[c.kind] = counts.get(c.kind, 0) + 1
    return counts
