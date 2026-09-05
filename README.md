# slopcheck

Check whether a vulnerability report's stated facts match the source tree it
claims to be about.

Read-only. Executes nothing. Downloads nothing. Produces evidence, not a verdict.

```
$ slopcheck report.txt --repo ./curl --ref HEAD

  8 contradicted   0 consistent   1 uncheckable

--- CONTRADICTED ---------------------------------------------
[X] path: packages/OS400/os400sys.c
     check    : file_exists
     observed : no such path at HEAD; a file with that name exists
                elsewhere: projects/OS400/os400sys.c

[X] symbol: Curl_ldap_err2string
     check    : symbol_exists
     observed : identifier appears nowhere in the tree at HEAD
```

That is a real report ([curl #3418528](https://hackerone.com/reports/3418528),
closed as spam). A maintainer reached the same two conclusions by hand. This
took 0.4 seconds.

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

Six real curl reports: four from the maintainers' own published archive of
rejected AI slop, two genuine (one a resolved CVE). Re-measured against a full
clone of curl at `8071d7adc2` (HEAD, 2026-09-05), no `--ref` given.

| report | label | contradicted | consistent | uncheckable | time |
|---|---|---|---|---|---|
| [2871792](https://hackerone.com/reports/2871792) | slop | 1 | 0 | 0 | 1.1s |
| [3125832](https://hackerone.com/reports/3125832) | slop | 16 | 2 | 5 | 6.4s |
| [3400831](https://hackerone.com/reports/3400831) | slop | 1 | 2 | 4 | 0.7s |
| [3418528](https://hackerone.com/reports/3418528) | slop | 8 | 0 | 1 | 1.1s |
| [3969255](https://hackerone.com/reports/3969255) | **genuine (CVE)** | **0** | 19 | 7 | 2.2s |
| [3973228](https://hackerone.com/reports/3973228) | **genuine** | **0** | 14 | 1 | 0.8s |

Zero contradictions on the genuine reports. That result is only trustworthy
because of what sits behind it, which is worth stating plainly: it depends
entirely on `recent_tags()` returning a correct list of release tags, and that
function shipped with three separate defects, each of which silently disabled
the stale-`--ref` downgrade or made it fire for the wrong reason.

1. A de-duplication key of `tag.rstrip("0123456789_-.")` collapsed every
   `curl-*` tag into one family, stopping the list at two entries.
2. Sorting by date put curl's three release candidates for 8.22.0 at the top:
   one point in history wearing four hats.
3. Fork variants leaked in. curl publishes `tiny-curl-*`, a cut-down embedded
   build; `ossl_connect_common` survives in `tiny-curl-8_4_0`. Counting that
   as a release makes the downgrade fire for a symbol that mainline deleted
   years ago — the right answer for entirely the wrong reason.

Fixed by dropping pre-releases, grouping tags by prefix, keeping only the
dominant (mainline) prefix, and walking back 14 distinct versions.
`ossl_connect_common` in report 3969255 is now downgraded because it is
genuinely present at `curl-8_12_1`, `curl-8_12_0` and `curl-8_11_1`, verified
directly against the tree rather than taken from the note.

**This widening costs recall, deliberately.** Report 3400831 falls from two
contradictions to one: `CURLX_SET_BINMODE` really did exist at `curl-8_16_0`,
so contradicting it was wrong. The surviving finding is the honest one — the
report cites `include/tool_binmode.h`, and that header lived at
`src/tool_binmode.h` before moving to `lib/curlx/binmode.h`. Never
`include/`. For a tool whose only asset is a maintainer trusting its
CONTRADICTED lines, trading recall for precision is the right direction.

Known gap: `check_path` does not consult the history probe at all, so a path
claim about an older release still comes back CONTRADICTED where a symbol
claim would be downgraded. `history_note(is_path=True)` exists and is
unused. That is the same defect class as the three above, on the other axis.

The *ratio* carries more signal than the count: genuine reports produce many
consistent claims because they cite real code precisely. n=6 remains an
anecdote, not an evaluation — see below.

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
