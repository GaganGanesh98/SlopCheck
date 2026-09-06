#!/usr/bin/env python3
"""Run slopcheck across a labelled corpus and report how well it discriminates.

This replaces the six hand-picked examples with a measurement. The headline
number is NOT accuracy -- it is the false-contradiction rate on confirmed
vulnerabilities. A tool that wrongly contradicts honest reporters is worse than
no tool, because a maintainer only has to be burned once to stop reading it.

    python3 tools/evaluate.py --corpus data/curl --repo curl-repo --ref HEAD

Read the caveats it prints. They are not boilerplate.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from slopcheck.checks import Tree, RepoCache, run, CONTRADICTED, CONSISTENT, UNCHECKABLE
from slopcheck.claims import extract


def score_one(args) -> dict:
    rec, corpus, repo, ref, cache = args
    text = (corpus / "reports" / f"{rec['id']}.txt").read_text(
        encoding="utf-8", errors="replace")
    tree_for_names = Tree(str(repo), ref, cache=cache)
    claims = extract(text, tree_for_names.basenames())
    # Fresh Tree per report so the history budget is per-report, but sharing
    # the RepoCache: file lists, blobs, tags and grep hits are facts about the
    # repository, identical for every report. Re-deriving them per report cost
    # ~10,000 git subprocesses over this corpus.
    tree = Tree(str(repo), ref, cache=cache)
    findings = run(tree, claims)
    t = {CONTRADICTED: 0, CONSISTENT: 0, UNCHECKABLE: 0}
    for f in findings:
        t[f.verdict] = t.get(f.verdict, 0) + 1
    return {
        "id": rec["id"], "label": rec["label"], "substate": rec["substate"],
        "claims": len(claims), "body_chars": rec["body_chars"],
        "contradicted": t[CONTRADICTED], "consistent": t[CONSISTENT],
        "uncheckable": t[UNCHECKABLE],
        "checks": [f.check for f in findings if f.verdict == CONTRADICTED],
    }


def pct(a: int, b: int) -> str:
    return f"{100.0 * a / b:5.1f}%" if b else "    -"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="data/curl")
    ap.add_argument("--repo", default="curl-repo")
    ap.add_argument("--ref", default="HEAD")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--labelled-only", action="store_true")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    corpus = Path(args.corpus)
    index = json.loads((corpus / "index.json").read_text())
    rows_in = [r for r in index
               if r["body_chars"] > 0
               and (not args.labelled_only or r["label"] != "unlabelled")]
    print(f"scoring {len(rows_in)} reports against {args.repo}@{args.ref} "
          f"({args.workers} workers)...", file=sys.stderr)

    cache = RepoCache()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(
            score_one, [(r, corpus, args.repo, args.ref, cache) for r in rows_in]))

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2))

    groups: dict[str, list[dict]] = {}
    for r in results:
        groups.setdefault(r["label"], []).append(r)

    print(f"\n{'=' * 74}\nSLOPCHECK ON {len(results)} curl REPORTS  "
          f"({args.repo}@{args.ref})\n{'=' * 74}")

    print(f"\n{'label':12s} {'n':>5s} {'any contra':>11s} {'med contra':>11s} "
          f"{'med consis':>11s} {'med claims':>11s}")
    print("-" * 74)
    for label in ("vuln", "slop", "unlabelled"):
        g = groups.get(label, [])
        if not g:
            continue
        anyc = sum(1 for r in g if r["contradicted"] > 0)
        print(f"{label:12s} {len(g):5d} {pct(anyc, len(g)):>11s} "
              f"{statistics.median(r['contradicted'] for r in g):11.1f} "
              f"{statistics.median(r['consistent'] for r in g):11.1f} "
              f"{statistics.median(r['claims'] for r in g):11.1f}")

    vuln, slop = groups.get("vuln", []), groups.get("slop", [])
    if vuln and slop:
        fp = [r for r in vuln if r["contradicted"] > 0]
        tp = [r for r in slop if r["contradicted"] > 0]
        print(f"\nAt the 'any contradiction' threshold:")
        print(f"  confirmed vulnerabilities wrongly contradicted : "
              f"{len(fp)}/{len(vuln)}  ({pct(len(fp), len(vuln)).strip()})")
        print(f"  archived slop reports flagged                  : "
              f"{len(tp)}/{len(slop)}  ({pct(len(tp), len(slop)).strip()})")
        if fp:
            worst = sorted(fp, key=lambda r: -r["contradicted"])[:8]
            print(f"\n  false contradictions to inspect by hand "
                  f"(these decide whether the tool is usable):")
            for r in worst:
                kinds = ", ".join(sorted(set(r["checks"])))
                print(f"    #{r['id']}  {r['contradicted']:2d} contra  [{kinds}]")

    silent = [r for r in results if r["claims"] == 0]
    print(f"\n  reports yielding no checkable claim at all: "
          f"{len(silent)}/{len(results)}  ({pct(len(silent), len(results)).strip()})")
    print("    -- correct behaviour for vague prose, but it means the tool has "
          "nothing\n       to say about them; they are not 'clean'.")

    print(f"""
CAVEATS -- read before quoting any number above
  1. Every report was checked against ONE ref ({args.ref}). Reports about older
     releases will contradict themselves purely because the code moved. The
     stale-ref downgrade mitigates this; it does not eliminate it. Numbers here
     are a LOWER bound on precision.
  2. 'slop' means membership in curl's published archive (~49 reports). It is
     small, and it is not a random sample -- the maintainers published the
     memorable ones.
  3. 'unlabelled' is mostly not-applicable and informative reports. Many are
     honest and out of scope. Do NOT treat that group as negatives.
  4. Reports were disclosed by curl at their discretion; recent months are
     under-represented.""")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
