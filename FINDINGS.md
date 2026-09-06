# Grounding a vulnerability report against its own source tree does not separate real reports from fabricated ones

**A negative result, plus a labelled corpus.**

Gagan Ganesh · September 2026
Code and data: https://github.com/GaganGanesh98/SlopCheck

*Figures correspond to the repository at tag `v1.0-negative-result` and are
reproducible from it.*

---

## Summary in one paragraph

Open-source maintainers are drowning in AI-written security reports that look
real and aren't. The obvious defence is to check the report's stated facts —
file paths, line numbers, function names, quoted code — against the actual
source code, on the theory that a made-up report will cite things that don't
exist. I built that checker, then built a labelled corpus of 557 real curl
security reports to test it on. **It doesn't work, and I can say precisely why
it doesn't work.** Genuine, curl-confirmed vulnerability reports get
contradicted at almost exactly the same rate as reports curl publicly archived
as AI slop. After five rounds of fixes that cut the tool's false alarms by 86%,
its ability to tell the two groups apart got *worse*, and ended up below what a
random number generator scores on the same data. The reason is structural: most
of what a checker finds in a report isn't a claim about the project at all —
it's the reporter's own proof-of-concept code being read as if it were a quote
from the codebase. That's a category error, and no amount of tuning fixes a
category error.

---

## 1. Why anyone would build this

Writing a plausible security report now costs almost nothing. Checking one
still costs a human expert an hour or more. That gap is being paid for by
unpaid volunteers.

What happened in 2026:

- **curl** shut down its bug bounty on 31 January after a flood of AI-generated
  submissions. The share of reports that turned out to be real fell from about
  15% to under 5%. It reopened on 25 February with no money attached.
- **Linux kernel** networking maintainer Jakub Kicinski, in a pull request:
  "We are completely overwhelmed." Security advisories per kernel release went
  from roughly 500 to a projected 2,000.
- **JFrog** found 55 advisories filed by a single account in July. 54 were
  fabricated. One had already been scored 10.0 Critical by Red Hat. Every one
  of them cited functions that don't exist or line numbers past the end of the
  file.

That last detail is the whole idea. If fake reports cite things that don't
exist, then a program that checks whether they exist should catch fakes. It's a
clean hypothesis and it is straightforwardly testable. So I tested it.

## 2. What I built

**SlopCheck** reads a vulnerability report, pulls out every factual claim that
a source tree could disagree with, and checks each one against a local git
clone.

Six checks:

| check | the claim it tests |
|---|---|
| `file_exists` | the cited path is actually in the tree |
| `line_in_range` | the cited line number is inside that file |
| `symbol_exists` | the named function or variable appears anywhere |
| `snippet_present` | quoted "source code" really comes from this project |
| `commit_exists` | a cited commit hash is in this repository |
| `version_tagged` | a cited version matches a real release tag |

It is read-only. It runs nothing, downloads nothing, and posts nothing. Pure
Python standard library, no model, no API key.

Three possible verdicts, and deliberately none of them is "this is slop":

- **CONTRADICTED** — the source tree positively disagrees with the report
- **CONSISTENT** — the tree agrees; this is *not* evidence the bug is real
- **UNCHECKABLE** — needs running code, or the claim is too vague to pin down

### Why it refuses to give a verdict

These constraints came from reading what maintainers actually said, not from
guessing:

1. **Never classify.** Bugcrowd's Chief AI Officer, OpenSSF and GitHub all say
   AI-text detectors don't work. curl's maintainer lists "AI security analysers
   dismissing valid reports" as a harm in its own right. So the tool shows
   evidence and never renders judgement.
2. **Never act on its own.** The Linux documentation says the assistant "must
   never send anything itself." LLVM bans agents acting in project spaces.
   FFmpeg: "Automated submissions are not accepted." Three projects drew the
   same line independently.
3. **Never filter silently.** curl requires every report to become public
   whether valid or not. A tool that quietly drops things is disqualified
   before it starts.
4. **Verification, not judgement.** Daniel Stenberg on why pull requests don't
   drown him: "we don't need to waste any human time on pull requests until the
   quality is good enough to get green check-marks from 200 CI jobs." He trusts
   mechanical checks. He does not trust opinions.

## 3. The corpus — the part that survives

Before measuring anything I needed something to measure against. Nobody had
assembled one, so I built it.

`tools/fetch_curl_corpus.py` pulls curl's disclosed HackerOne reports from
public, unauthenticated endpoints. One request per second, resumable,
identifies itself honestly in the User-Agent.

**557 curl security reports, 2.5 million characters:**

- **126 confirmed vulnerabilities** (HackerOne state `resolved`) — gold positives
- **49 reports from curl's own published AI-slop archive** — gold negatives
- **382 unlabelled** — mostly not-applicable and informational

One honest caveat that matters: `not-applicable` does **not** mean slop. Plenty
of those are honest reports that were simply out of scope. Treating that group
as negatives would inflate every number in this document, so I didn't.

The slop label set is 49 reports and it is not a random sample — maintainers
published the memorable ones. That's a real limitation, and it cuts *against*
the tool: the archived reports are the most obviously fake ones available, the
easiest possible test, and the tool still can't separate them.

This corpus is reusable by anyone testing any approach to this problem. It is
the durable contribution here.

## 4. What the measurement showed

Every report checked against the same curl clone. "Flagged" means the report
produced at least one CONTRADICTED finding.

| version of the tool | total contradictions | genuine reports flagged | archived slop flagged | separation (Youden J) | per-finding precision |
|---|--:|--:|--:|--:|--:|
| first working version | 3,195 | 73.0% | 83.7% | — | — |
| after demoting `snippet_present` | 1,859 | 57.9% | 73.5% | 0.155 | 2.5% |
| after mechanical bug fixes | 471 | 33.3% | 30.6% | — | 7.5% |
| after provenance rules | 336 | 32.5% | 28.6% | 0.076 | 7.5% |
| after line stale-ref + commit guard | **264** | **29.4%** | **28.6%** | **0.083** | **10%** |

The last row is the finished tool. Earlier drafts of this document stopped at
the fourth row; the two remaining fixes were then made, and changed nothing
that matters — which is itself part of the result.

Youden J is just "how much better than a coin flip." J = 0 means the tool is
flipping a coin. J = 1 means perfect separation.

Read the last row carefully. **The finished, debugged, five-rounds-of-fixes
version flags genuine vulnerability reports slightly *more often* than it flags
known-fabricated ones.** The sign is inverted. It is not merely useless; on this
corpus it points the wrong way.

### The noise floor

To know whether J = 0.083 is bad, you need to know what nothing at all scores.
I generated 2,000 random features with no connection to the report content and
swept thresholds on them exactly the same way — post-hoc best threshold, same
group sizes (126 vs 49). These figures were reproduced independently from a
different seed, agreeing to within 0.002.

```
median best-J from pure noise      0.092
90th percentile                    0.178
95th percentile                    0.203
max over 2,000 noise features      0.331
```

Two things follow. First, the *best* number the tool ever achieved — J = 0.155,
at the stage where it looked most promising — is beaten by **17.1% of pure
noise features.** One in six random numbers does better. That was never weak
signal; it was no signal.

Second, the finished tool at J = 0.083 separates real from fake **worse than the
median coin flip** — 57% of pure-noise features beat it.

There's a warning in here for anyone continuing this line of work. Try five
independent candidate signals and keep the best, and pure noise hands you
J = 0.162 — higher than anything this tool ever reached. Any new feature family
will produce an encouraging number whether or not it means anything. Without a
noise baseline you cannot tell the difference, and I nearly didn't.

### The fixes worked. They just didn't help.

This is the part I find most instructive. Across four review rounds the tool
got substantially better as software:

- Total findings dropped 86% (1,859 → 264) — those were false alarms and they
  are genuinely gone.
- Per-finding precision tripled (2.5% → 7.5%) between the first and second
  round.
- And then it **stopped moving** — 7.5%, 7.5%, 10% across the last three
  rounds, while another 207 findings were removed. The samples are 40 findings
  each, so a 7.5-to-10 drift sits well inside sampling noise.

When precision refuses to move while you delete two-thirds of the output, the
errors you're deleting and the errors you're leaving are the same kind of
error. You are not chipping away at a bug list. You have hit the floor of the
approach.

At 10% per-finding precision, a maintainer reading the output sees **roughly
nine wrong findings for every correct one.**

## 5. Why it fails — the actual cause

The extractor reads the *report's own proof-of-concept code* as if it were a
claim about the project.

A genuine report looks like this:

> Here's a test harness that reproduces it:
> ```c
> int main(void) { CURL *c = curl_easy_init(); trigger_overflow(c); }
> ```

`trigger_overflow` is the reporter's own function, in the reporter's own test
file. The tool searches curl's source tree, doesn't find it, and reports that
curl's source disagrees with the report. But curl's source has no opinion about
a function that lives in someone else's test file. Nothing was contradicted.
The question was malformed.

This is a **category error**, not a measurement error. The tool is confidently
answering a question nobody asked. And it isn't fixable by better regex,
because the distinction — "is this string a claim about the project, or a thing
the reporter wrote?" — requires understanding what the paragraph is *doing*,
which is exactly the judgement the design constraints in §2 forbid the tool
from making.

Worse, the error is *anti-correlated* with what you want. Genuine reports
contain more PoC code than fabricated ones, because genuine reporters actually
reproduced the bug. So the check that fires most often fires hardest on the
reports you most want to leave alone.

### A concrete illustration, including one of my own mistakes

While writing the README I picked report **3418528** as the flagship example of
the tool catching a fabrication. It cited
`packages/OS400/os400sys.c` and a function `Curl_ldap_err2string`. Neither was
at curl's HEAD, so I wrote it up as invented.

Half of that was wrong. `packages/OS400/os400sys.c` was a real file in curl
through version 8.18.0; it moved to `projects/` in commit `3ee1d3b573`. Only
the *symbol* was fabricated. I had checked the wrong point in history and
produced exactly the failure mode the tool produces.

That is the tool's central weakness, demonstrated on its own author, in its own
documentation. The same thing happened a second time with the symbol
`ossl_connect_common` — which appeared to still exist only because
`tiny-curl-8_4_0`, a cut-down fork variant, had leaked into the release-tag
list.

Both are now fixed. Missing symbols and paths get checked against recent
release tags, and if found there the verdict is downgraded to UNCHECKABLE with
a note telling the user which `--ref` to re-run with. That mitigation is worth
about two percentage points. It does not save the approach.

### The polarity artefact

The clearest single illustration is report **3650689**, which states in prose:

> There is no `smb_conns_match` equivalent in `url_match_proto_config`.

The tool contradicts the reporter — by confirming that `smb_conns_match`
appears nowhere in the tree. It has no notion of polarity: an assertion that
something is absent and an assertion that something is present are the same
query to a grep, so agreeing with the reporter is reported as disagreeing.

## 6. Three follow-up hypotheses, one tested

I proposed three additional signals that might work where raw grounding
doesn't. One was cheap enough to test properly:

**Conditional constraint discontinuity** — the idea that fabricated reports
describe trigger conditions that don't hang together (a condition on line 40
that the code path on line 12 has already made impossible). Measured as a
difference-in-differences against the labelled sets: **null, with the sign
inverted, p = 0.644.** No effect.

The other two (temporal dispersion of cited artefacts; the graph topology of
claims within a report) are untested. Given that the two tested signals both
came back null-or-inverted, I would want a strong prior reason before spending
weeks on a third.

## 7. What this means for the field

**Report-versus-source-tree grounding is a solved question and the answer is
no.** Anyone reaching for it as a first defence — and it is the obvious first
reach — can now skip it, or start from this corpus and prove me wrong.

What remains open:

- **Execution grounding**, with a large caveat. "I Can't Believe It's Not a
  Valid Exploit" (arXiv:2602.04165) found that **71.5% of proof-of-concepts an
  automated harness scored as successful were invalid** — hard-coded outcomes,
  swallowed exceptions, reimplemented behaviour. Exit codes are forgeable.
  Proving a PoC actually reached the claimed code path needs instrumentation
  that doesn't exist yet. Anyone attempting it should build on ARVO
  (BSD-2, github.com/n132/ARVO): 6,138 real vulnerabilities as paired
  vulnerable/patched Docker images.
- **The volume problem, not the fabrication problem.** Greg Kroah-Hartman said
  in March 2026 that kernel reports had *stopped* being obvious fakes and become
  real — just overwhelming in number. If that generalises, fabrication
  detection is the shrinking half of the problem and prioritisation is the
  growing half. Nothing in this project touches prioritisation.
- **The standards route.** OpenSSF issue #178, "AI-SLOP: Develop best current
  practises for Open Source maintainers," is open and barely started. The
  design constraints in §2 are a contribution to that conversation independent
  of whether any tool works.

## 8. Honest limitations of this result

- One project. Everything here is curl. The corpus builder takes any HackerOne
  handle, so this is testable on Node.js or others, and I haven't done it.
- 49 gold negatives, non-randomly selected.
- Everything checked against one git ref, so the false-contradiction numbers
  are an upper bound on the tool's error and the precision numbers are a lower
  bound.
- The per-finding precision figures come from hand-adjudicating four samples of
  40 findings each — 160 in total, drawn fresh at random after each round of
  fixes — not the full output. Two of the four correct findings in the final
  sample come from one report, so they are not independent.
- 6.3% of reports yield no checkable claim at all. That's correct behaviour for
  vague prose, but those reports are not "clean" — the tool simply has nothing
  to say about them.

## 9. How the result was arrived at

Worth stating, because it is the reason the result exists.

The acceptance test was written to *falsify* the tool's headline claim rather
than confirm it. An early six-report demo showed zero false alarms on genuine
reports; only the 557-report corpus revealed that the real rate was 73%. Every
figure was independently reproduced before being accepted, including figures I
produced myself — three of mine failed to reproduce and were replaced. Nine or
more defects were found across five review rounds, one of which
(non-deterministic output caused by iterating a Python `set`) was only caught
because a test compared observed output *text* across 9,590 findings rather
than just counting verdicts. A verdict-only test would have passed.

Two defects found in the final adjudication round were left unfixed on purpose
and are documented in the README: a path-suffix test that runs one way only,
and a project-frame check defeated by basename collision. Both are enumerable
and patchable. Five rounds of exactly that moved precision not at all, and
continuing is how a negative result gets talked out of existence one plausible
fix at a time.

The tool doesn't work. I know that with more confidence than most people know
their tools do work.

---

## Reproducing this

```bash
git clone https://github.com/GaganGanesh98/SlopCheck && cd SlopCheck
git clone https://github.com/curl/curl curl-repo          # full clone, not blobless
python3 fetch_curl_corpus.py --out data/curl              # ~10 min at 1 req/sec
python3 evaluate.py --corpus data/curl --repo curl-repo --ref HEAD
```

The report bodies are not vendored here — they were written by third parties
and published under HackerOne's terms. The index and the fetcher reproduce
them.

Tests: `python3 -m pytest` (80 passing, synthetic git fixtures, no network).
