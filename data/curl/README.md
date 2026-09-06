# Corpus card — 557 curl security reports

Built by `fetch_curl_corpus.py` from HackerOne's public, unauthenticated
disclosure endpoints for the `curl` programme. One request per second,
resumable, honest User-Agent.

## What is here

| file | contents |
|---|---|
| `index.json` | one record per report: id, title, substate, URL, timestamps, CVE ids, body length, label |
| `index.csv` | the same, flattened |
| `reports/` | **not tracked.** Rebuild with `python3 fetch_curl_corpus.py --out data/curl` |

The report bodies are not vendored. They were written by third parties and
published under HackerOne's terms rather than this repository's licence, so
what is committed is the corpus *definition* and the fetcher that reconstructs
it. This is the ordinary arrangement for a scraped corpus: fully reproducible,
nothing redistributed.

## Labels

| label | n | meaning |
|---|--:|---|
| `vuln` | 126 | HackerOne substate `resolved` — curl confirmed and fixed it. Gold positives. |
| `slop` | 49 | listed in curl's own published AI-slop archive. Gold negatives. |
| `unlabelled` | 382 | everything else, mostly `not-applicable` and `informative`. |

## Three caveats that change how you may use this

**`not-applicable` does not mean slop.** Many of those reports are honest and
simply out of scope — wrong project, known behaviour, no security impact.
Treating the unlabelled group as negatives will inflate any result you compute.
Do not do it.

**The 49 slop reports are not a random sample.** The maintainers published the
memorable ones. They are the most obviously fabricated reports available, which
makes them the *easiest* possible test — a method that cannot separate these
will not separate subtler ones.

**Recent months are under-represented.** Reports are disclosed at curl's
discretion, and disclosure lags submission.

## Provenance and ethics

Every report in this corpus was already public and attributed on HackerOne
before it was collected. Nothing here was obtained through authentication, and
no non-public data is included.
