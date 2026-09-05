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
reports, this tool contradicts 57.9% of confirmed vulnerabilities.** It does
not work as a gate. See [Measured behaviour](#measured-behaviour) — that section is
the honest summary of what this does and does not do, and the example above is
an illustration of the mechanism, not a result.

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

Exit code is `1` when anything is contradicted, so it can gate a CI job. That
is a signal for a human to look — never grounds to close a report.

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
| **confirmed vulnerabilities** | 126 | **57.9%** |
| archived slop | 49 | 73.5% |
| unlabelled | 382 | 61.0% |

**73 of 126 genuine, curl-confirmed vulnerability reports are contradicted.**
The separation between real and fake is about fifteen points. As a gate — "any
contradiction means look here" — that is useless, and worse than useless if a
maintainer trusts it.

Those figures are after demoting `snippet_present` (below). As originally
shipped the tool contradicted **73.0%** of confirmed vulnerabilities against
83.7% of slop: a ten-point gap.

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

Close to 4:1 against. Demoting it improves discrimination rather than trading
it away: the gap to slop *widens* from +10.7 to +15.6 points while false
contradictions on genuine reports fall from 73.0% to 57.9%. Absolute catch
rate was never the goal; separation is.

### Ablations on the original checks

| disabled | genuine wrongly flagged | slop caught |
|---|---|---|
| nothing (as originally shipped) | 73.0% | 83.7% |
| snippet *(now the default)* | **57.9%** | 73.5% |
| snippet + line + commit | 54.8% | 73.5% |
| snippet + line + file | 43.7% | 46.9% |

Nothing beyond the snippet fix pays for itself: the remaining options buy a
few points of precision by destroying slop detection.

### What this means

The binary gate is still the wrong product, and the exit code should not be
read as a verdict. 57.9% is a narrower hole than 73.0%, not a closed one. What survives is what the design notes said before the
implementation drifted: **an annotator, not a gate.** Individual findings are
frequently correct and useful — *this symbol is absent at HEAD but present at
8.12.1; this file moved here; this line is past end-of-file* — even where the
aggregate carries no signal. A maintainer skims the transcript in ten seconds
and decides.

Caveats that limit every number above: all reports were scored against one ref
(HEAD), so this is a lower bound on precision; the slop label is membership in
a small, non-random published archive; and `unlabelled` is mostly
not-applicable and informative reports, many of them honest and out of scope —
it is not a negative class. `evaluate.py` prints these with its output.

### Reproducing

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
