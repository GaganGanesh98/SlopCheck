# slopcheck

Check whether a vulnerability report's stated facts match the source tree it
claims to be about.

Read-only. Executes nothing. Downloads nothing. Produces evidence, not a verdict.

```
$ slopcheck report.txt --repo ./curl --ref HEAD

  7 contradicted   0 consistent   2 uncheckable

--- CONTRADICTED ---------------------------------------------
[X] symbol: Curl_ldap_err2string
     check    : symbol_exists
     observed : identifier appears nowhere in the tree at HEAD

--- UNCHECKABLE ----------------------------------------------
[?] path: packages/OS400/os400sys.c
     check    : file_exists
     observed : no such path at HEAD; a file with that name exists
                elsewhere: projects/OS400/os400sys.c — but it IS
                present at curl-8_18_0, curl-8_17_0, curl-8_16_0;
                the report may describe an older release, so re-run
                with --ref set to the version the reporter named
```

That is a real report ([curl #3418528](https://hackerone.com/reports/3418528),
closed as spam). This took 1.9 seconds.

Note which claim survives as CONTRADICTED and which does not, because an
earlier version of this README got it wrong. `Curl_ldap_err2string` is
invented, and that is exactly the finding curl's maintainer made by hand:
*"This function does not exist... It is made up."* But the **path claim was
honest**. `packages/OS400/os400sys.c` really did exist in curl through 8.18.0
and moved to `projects/` in `3ee1d3b573` ("tidy-up: merge root `packages`
directory into `projects`"). Checking against HEAD alone called a truthful
line fabricated. A tool that does that to a reporter deserves to be ignored.

**Before reading further: measured across all 557 publicly disclosed curl
reports, this tool contradicts 29.4% of confirmed vulnerabilities, and 10% of
its individual contradictions are correct.** It does not work as a gate, and it
does not yet work as an annotator either. See [Measured
behaviour](#measured-behaviour) — that section is the honest summary of what
this does and does not do, and the example above is an illustration of the
mechanism, not a result.

---

## Why this exists

Producing a plausible vulnerability report now costs pennies. Verifying one
still costs an hour of expert time. That asymmetry is being paid for by unpaid
maintainers, and they are quitting.

- **curl** shut down its bug bounty in January 2026 after seven fake reports
  arrived in sixteen hours. Valid submissions had fallen from ~15% to under 5%.
- **Linux kernel** networking maintainers: *"We are completely overwhelmed."*
  Advisories per release went from ~500 to a projected 2,000.
- **JFrog** found 54 entirely fabricated CVE advisories from a single account,
  one initially rated 10.0 Critical. Every one cited functions that don't
  exist, or line numbers past the end of the file.

All 54 of those would have died to four static checks against a source tree.
Nobody had built them.

## What it is not

Deliberately, and after reading what maintainers actually asked for:

- **Not a classifier.** It never says "this is AI slop". Every authority on
  this — Bugcrowd's Chief AI Officer, OpenSSF, GitHub — says AI-text detection
  does not work, and none has published numbers to the contrary. Building on
  stylometry means betting against the field.
- **Not autonomous.** It does not post, comment, label, or close anything.
  The Linux kernel, LLVM and FFmpeg all independently drew this exact line:
  *"the assistant must never send anything itself."*
- **Not a filter.** curl's stated requirement is that *all* reports become
  public, valid and invalid alike. A tool that silently drops things is
  disqualified. This one produces a transcript you attach to the report.
- **Not proof of anything.** `CONSISTENT` means the tree does not disagree.
  It is not evidence a bug is real. Reproduction is still required.

The design principle comes from Daniel Stenberg explaining why pull requests
don't drown him the way reports do: *"we don't need to waste any human time on
pull requests until the quality is good enough to get green check-marks from
200 CI jobs."* He trusts **verification**, not classification. This is CI for
the factual claims in a report.

## Verdicts

There are three, and none of them is a judgement about the reporter.

| | meaning |
|---|---|
| `CONTRADICTED` | the tree positively disagrees — file absent, line past EOF, symbol nowhere |
| `CONSISTENT` | the tree agrees; **not** evidence the bug is real |
| `UNCHECKABLE` | needs execution, or the claim is too vague to bind to anything |

## Checks in v1

| check | claim it tests |
|---|---|
| `file_exists` | the cited path is in the tree at this ref |
| `line_in_range` | the cited line number is within that file |
| `symbol_exists` | the named identifier appears at all (whole-word) |
| `snippet_present` | quoted "source code" actually comes from this project |
| `commit_exists` | a cited commit hash is in this repository |
| `version_tagged` | a cited version corresponds to a real tag |

Each contradiction names what was observed, so a maintainer can check the
tool rather than trust it.

## Install and run

Python 3.10+, git. No other dependencies.

```bash
git clone <this repo> && cd slopcheck
git clone https://github.com/curl/curl.git curl-repo    # full clone, see below

python3 -m slopcheck.cli examples/curl-3418528.txt --repo curl-repo
python3 -m slopcheck.cli report.txt --repo ./target --ref curl-8_11_0 --json
python3 -m slopcheck.cli report.txt --repo ./target --claims-only
```

**The exit code reports whether the tool ran, not whether the report is
suspect.** `0` means it produced a report, `2` means it could not run (bad
`--ref`, missing `--repo`). Contradictions do not affect it.

That is deliberate, and it is a breaking change from earlier versions which
exited `1` on any contradiction. `--fail-on-contradiction` restores the old
behaviour opt-in. See [There is no usable threshold](#there-is-no-usable-threshold)
for why you probably should not use it.

**Use a full clone.** On a blobless clone (`--filter=blob:none`) every
cross-ref probe lazily refetches blobs over the network and the run appears to
hang. slopcheck detects this and disables history probing, but you lose the
most useful check.

**`--ref` matters more than anything else.** A report about curl 8.11 checked
against `HEAD` will contradict itself purely because the code moved. When a
symbol is missing at your ref, slopcheck greps recent release tags and, if it
finds it, downgrades the finding to `UNCHECKABLE` with a note telling you to
re-run against the right version. Set `--ref` to what the reporter named.

## Measured behaviour

**The headline result is negative.** Read this section before the rest of the
README; an earlier version of it reported six hand-picked reports and showed
zero contradictions on the two genuine ones. That was a demo, not evidence, and
it was unrepresentative.

`fetch_curl_corpus.py` builds a labelled corpus from HackerOne's public
disclosures: **557 curl reports — 126 confirmed vulnerabilities (`resolved`),
49 in the maintainers' published AI-slop archive, 382 unlabelled.**
`evaluate.py` scores all of them against one ref.

| | n | got ≥1 contradiction |
|---|---|---|
| **confirmed vulnerabilities** | 126 | **29.4%** |
| archived slop | 49 | 28.6% |
| unlabelled | 382 | 24.9% |

**37 of 126 genuine, curl-confirmed vulnerability reports are contradicted —
and slop is contradicted no more often than they are.** The separation between
real and fake is negative. As a gate — "any contradiction means look here" —
that is not merely useless, it points the wrong way.

Earlier revisions showed 57.9% against 73.5%, a fifteen-point gap that looked
like weak-but-real signal. It was not. Six classes of extraction bug (below)
were removed, cutting total contradictions from 1,859 to 264, and the gap went
with them. That is what a gap made of noise does when the noise goes.

### It is not the stale-ref problem

That was the obvious hypothesis and it is wrong. Split by year filed, recent
reports contradict *more*, not less:

```
2019  60.0%     2022  73.9%     2025  81.8%
2020  66.7%     2023  72.2%     2026  79.5%
2021  46.2%     2024  81.8%
```

### What was actually broken

Share of false contradictions on confirmed vulnerabilities, as originally
shipped:

```
snippet_present   35.5%      file_exists     18.6%
symbol_exists     21.5%      commit_exists    3.8%
line_in_range     20.5%
```

`snippet_present` was unsound by construction. It demanded that quoted code
appear verbatim in the tree, but reporters quote their own proof-of-concept
code, build steps, illustrations and patches. Three lines it rejected on
*confirmed* vulnerabilities:

- `mkdir c:\usr\local\ssl` — a build instruction
- `void *ptr2 = realloc(ptr, len);` — the reporter's own illustration
- `static CURLUcode seturl(const char *url, CURLU *u, unsigned int flags)` — a
  real signature that has since changed

The check was written on the theory that fabricated reports quote invented
code. They do. So does everyone else, for different reasons.

**It no longer produces CONTRADICTED.** That is a semantics fix, not a tuning
choice: `CONTRADICTED` asserts the tree positively disagrees, and an absent
quoted line asserts nothing of the kind — the tree simply has nothing to say.
It now returns UNCHECKABLE.

The decisive measurement was not "how much slop detection does it cost" but
"what does it uniquely catch" — reports where `snippet_present` was the *only*
contradiction:

| | sole contradiction |
|---|---|
| confirmed vulnerabilities | **19 / 126** — pure false alarms |
| archived slop | **5 / 49** — real detections lost |

Close to 4:1 against. Demoting it appeared to improve discrimination rather
than trade it away: the gap to slop *widened* from +10.7 to +15.6 points while
false contradictions on genuine reports fell from 73.0% to 57.9%.

That fifteen-point gap is the one later rounds dissolved. All figures in this
subsection and the next are from that intermediate stage and are superseded by
the headline table; they are kept because the sequence is the finding.

### Ablations on the original checks

These ablations were measured on the pre-provenance pipeline and are kept for
the record; the absolute numbers are superseded by the table above.

| disabled | genuine wrongly flagged | slop caught |
|---|---|---|
| nothing (as originally shipped) | 73.0% | 83.7% |
| snippet *(now the default)* | **57.9%** | 73.5% |
| snippet + line + commit | 54.8% | 73.5% |
| snippet + line + file | 43.7% | 46.9% |

Nothing beyond the snippet fix pays for itself: the remaining options buy a
few points of precision by destroying slop detection.

### There is no usable threshold

The obvious response to a false-contradiction rate this high — 57.9% at the
time this was first run, 29.4% today — is to stop gating on "any
contradiction" and pick a better threshold. That is testable, so it was
tested rather than argued about. Sweeping every threshold on three metrics
across all 557 reports:

| metric | best threshold | genuine FP | slop caught | Youden J |
|---|---|---|---|---|
| contradiction count | ≥ 2 | 11.9% | 14.3% | 0.024 |
| contradicted / consistent | ≥ 0.1 | 18.3% | 26.5% | **0.083** |
| contradicted / claims | ≥ 0.2 | 9.5% | 16.3% | 0.068 |

Youden's J is `sensitivity + specificity - 1`: **J = 0 is a coin flip, J = 1 is
perfect.** The best result anywhere in the sweep is 0.083. At the natural
operating point — any contradiction at all — J is **−0.008**.

For scale: a randomly generated feature, swept the same way at the same class
sizes (n = 126 / 49), reaches a median best-J of **0.092**. The tool separates
real from fake slightly *worse* than the median coin flip. And it got there by
being fixed: the pre-fix pipeline scored 0.155, so most of the apparent signal
was the noise.

Every operating point with a false-alarm rate a maintainer would tolerate is
worthless:

```
contradiction count >= 15     genuine FP  6.3%    slop caught  2.0%
contradicted/claims >= 0.5    genuine FP  7.9%    slop caught  8.2%
```

Get the false alarms down to something honest and you catch roughly one slop
report in twelve. The aggregate signal is not in the data, so this is not a
tuning problem and no threshold fixes it.

### Per-finding accuracy: 10%

"The aggregate carries no signal, but individual findings are useful" was this
project's fallback position for a while. It is measurable, so it was measured
rather than asserted: draw contradictions at random, check each against the
tree by hand, count.

Three samples of 40, each drawn fresh at random after the pipeline changed:

| pipeline | contradictions | correct in a sample of 40 |
|---|---:|---:|
| as originally shipped | 1,859 | 1 (2.5%) |
| + three mechanical fixes | 471 | 3 (7.5%) |
| + provenance rules | 336 | 3 (7.5%) |
| + line stale-ref, commit guard | **264** | **4 (10%)** |

**Eighty-six percent of the output is gone and the precision did not move.**
That is the result, and it is stronger than any of the four numbers alone. Had
the residual been more enumerable bugs, removing six-sevenths of the output
would have concentrated the correct findings; instead each fix removed right
and wrong alike, in proportion. Nine wrong findings per correct one is not an
annotator a maintainer would read twice, and not one a reporter would run
twice either.

(Two of the four correct findings in the last sample come from a single slop
report, so they are not independent.)

What the wrong findings are, in the final sample:

| cause | share |
|---|---:|
| the reporter's own artifacts and prose nouns, in unfenced text | 35% |
| third-party API (OpenSSL, wolfSSL, GnuTLS, glibc, Apple Security) | 20% |
| stale ref beyond the 14-release probe window | 15% |
| a bare `line N` bound to the wrong nearby path | 10% |
| path shape — an include path or a path missing its `lib/` prefix | 5% |
| a real symbol cited with the wrong case (`curl_cookie_getlist`) | 2.5% |

Two specific defects visible in that sample, left unfixed deliberately:
`vauth/ntlm.c` contradicts because the suffix test runs one way only and the
report merely dropped the `lib/`; and an OpenSSL stack frame passed the
project-frame test because the line happens to mention `digest.c`, which
collides with curl's `lib/vauth/digest.c`.

Both are enumerable and both are patchable, which is the point. Six rounds of
exactly this produced no movement in precision. The seventh will not either,
and continuing to enumerate them is how a negative result gets talked out of
existence one plausible fix at a time.

### The artefact that says it best

Report 3650689 states, in prose:

> There is no `smb_conns_match` equivalent in `url_match_proto_config`.

The tool contradicts them — by confirming that `smb_conns_match` appears
nowhere in the tree. It has no notion of polarity: an assertion that something
is absent and an assertion that something is present are the same query, and
agreeing with the first one is reported as disagreement.

### What this means

Three deployments were considered for this tool, and the measurements close all
three:

- **A gate for maintainers.** Dead. The sweep settles it, and the separation is
  now negative.
- **An annotator for maintainers.** Dead. At 10% per-finding precision a
  maintainer reads nine wrong findings per useful one.
- **A linter for reporters, run before submission.** This was the strongest
  remaining argument: a false alarm costs the author ten seconds because it is
  *their* claim being questioned, so a high false-alarm rate might be
  affordable. That argument assumed the findings were individually
  mostly-right. At nine wrong per correct, a reporter runs it once, sees a
  dozen bogus complaints about their own PoC and about OpenSSL's API, and never
  runs it again. The economics do not hold at this precision.

That is not three failures. It is one failure, correctly located: **the tool
cannot tell which parts of a report are claims about the project.** Prose,
proof-of-concept source, third-party stack frames and the reporter's own build
paths all read alike to a static extractor, and the checks downstream are only
as good as that distinction.

The polarity artefact above is the clearest single illustration of it, and is
worth more than any of the tables here.

Caveats that limit every number above: all reports were scored against one ref
(HEAD), so this is a lower bound on precision; the slop label is membership in
a small, non-random published archive; and `unlabelled` is mostly
not-applicable and informative reports, many of them honest and out of scope —
it is not a negative class. `evaluate.py` prints these with its output.

### Reproducing

The report **bodies are not redistributed here.** They were written by third
parties and published under HackerOne's terms, not this repository's licence.
What is committed is the index — ids, labels, substates, CVE ids, URLs — plus
the fetcher that reconstructs the text, which is the ordinary arrangement for a
scraped corpus: fully reproducible, nothing redistributed.

They were committed in earlier revisions and remain in this repository's git
history. That was left alone deliberately. The content is curl's own publicly
disclosed reports, already published and attributed on HackerOne; rewriting
public history would break every existing clone to remove something that is a
`git clone` away from its actual source.

```bash
python3 fetch_curl_corpus.py --out data/curl        # ~10 min, rate limited, resumable
python3 evaluate.py --corpus data/curl --repo curl-repo --ref HEAD
```

Scoring 557 reports takes about two minutes. A shared `RepoCache` derives
repository facts (file lists, blobs, tags, grep hits) once rather than once per
report, and greps are batched — `git grep -o` names the matched pattern, so one
call with many `-e` patterns partitions exactly back to per-needle answers.
Together that cut git subprocesses from 20,295 to 4,160 with all 9,590
findings byte-identical.

## Roadmap

**Next: a real evaluation set.** HackerOne serves disclosed reports as JSON
without authentication. curl has 557 public ones: 126 confirmed vulnerabilities,
49 in the maintainers' published slop archive, and full triage threads
containing the adjudication in the maintainers' own words. Nobody has assembled
this. It is a few hours of polite scraping and it is the foundation for any
honest claim about how well this works.

**Then: execution grounding.** The deep problem, and the reason this stops at
static checks for now. "I Can't Believe It's Not a Valid Exploit"
([arXiv:2602.04165](https://arxiv.org/html/2602.04165v1)) found that **71.5% of
proof-of-concepts an automated harness scored as successful were invalid** —
they hardcoded the outcome, swallowed exceptions, or reimplemented the bug
rather than triggering it. Exit codes and success markers are forgeable. Proving
a PoC executed the claimed code path needs instrumentation, and no general tool
exists. Anything before that is theatre.

For the reproduction half, don't rebuild: [ARVO](https://github.com/n132/ARVO)
(BSD-2) ships 6,138 real vulnerabilities as paired vulnerable/patched Docker
images, two `docker run` commands away.

**Sandboxing, when it comes to that.** Default-deny egress enforced outside the
sandbox, plus a canary that fails the run if it can reach the network. Anthropic
had 3 of 141,006 evaluation runs touch production systems in July 2026; the
cause was not an escape but a misconfiguration that left egress open while the
prompt claimed otherwise. Assert nothing; test it every run.

## Prior art

The closest things that exist are [ProjectDiscovery
Triage](https://projectdiscovery.io/triage) and [HackerOne Hai
Triage](https://docs.hackerone.com/en/articles/13603896-agentic-validation).
Both are closed, both verify against a **live running web target**, and
HackerOne's own docs limit it to browser-reachable, unauthenticated
reproduction. Report-plus-source-tree is a different problem and nobody
occupies it.

[OpenSSF issue #178](https://github.com/ossf/wg-vulnerability-disclosures/issues/178),
"AI-SLOP: Develop best current practises for Open Source maintainers", is the
open venue. It is at 1 of 41 items complete and states plainly that there is
"no reliable technical indicator" for AI slop today. A working implementation
would land there with weight.

## Licence

MIT.
