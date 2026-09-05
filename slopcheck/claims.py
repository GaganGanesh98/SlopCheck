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


def extract(text: str) -> list[Claim]:
    """Return de-duplicated claims, in a stable order."""
    out: list[Claim] = []
    seen: set[tuple] = set()

    def add(c: Claim) -> None:
        if c.key() not in seen:
            seen.add(c.key())
            out.append(c)

    # file:line pairs bind a line number to a specific file -- strongest form
    for m in _PATH_LINE.finditer(text):
        path, line = m.group(1), m.group(2)
        add(Claim("path", path, _sentence_around(text, m.start())))
        add(Claim("line", line, _sentence_around(text, m.start()), {"path": path}))

    paths = [m.group(1) for m in _PATH.finditer(text)]
    for m in _PATH.finditer(text):
        add(Claim("path", m.group(1), _sentence_around(text, m.start())))

    # bare "line N" claims attach to the nearest preceding path, if any
    for m in _LINE_WORD.finditer(text):
        prior = [p for p in _PATH.finditer(text[: m.start()])]
        path = prior[-1].group(1) if prior else ""
        for n in _expand_numbers(m.group(1)):
            add(Claim("line", n, _sentence_around(text, m.start()),
                      {"path": path} if path else {}))

    symbols: set[str] = set()
    for pat in (_LABELLED, _TICKED, _CALL):
        for m in pat.finditer(text):
            name = m.group(1)
            low = name.lower()
            if low in _STOPWORDS or low in _STDLIB or name.isdigit():
                continue
            if not _looks_like_code(name):
                continue
            if name not in symbols:
                symbols.add(name)
                add(Claim("symbol", name, _sentence_around(text, m.start())))

    for m in _SHA.finditer(text):
        sha = m.group(1)
        # Pure digits are register dumps, timestamps and Suricata sids, not
        # commit hashes. Require at least one hex letter, and 8+ chars unless
        # the word "commit" immediately precedes it.
        if sha.isdigit():
            continue
        labelled = re.search(r"commit\s+$", text[: m.start()], re.I)
        if len(sha) >= 8 or labelled:
            add(Claim("commit", sha, _sentence_around(text, m.start())))

    for m in _CVE.finditer(text):
        add(Claim("cve", m.group(0).upper(), _sentence_around(text, m.start())))

    for m in _VERSION.finditer(text):
        if m.group(1).count(".") > 2:
            continue  # dotted quad or longer: an address, not a version
        add(Claim("version", m.group(1), _sentence_around(text, m.start())))

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
