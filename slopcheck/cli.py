from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .claims import extract, summarise
from .checks import Tree, run
from .report import to_json, to_text, tally, CONTRADICTED


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="slopcheck",
        description="Check a vulnerability report's stated facts against a source tree. "
                    "Read-only. Executes nothing. Produces evidence, not a verdict.",
    )
    ap.add_argument("report", help="path to the report text, or '-' for stdin")
    ap.add_argument("--repo", help="path to a local git clone of the target "
                                    "(not needed with --claims-only)")
    ap.add_argument("--ref", default="HEAD", help="tag, branch or commit to check against")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--all", action="store_true", help="also show consistent claims")
    ap.add_argument("--claims-only", action="store_true", help="print extracted claims and stop")
    ap.add_argument("--fail-on-contradiction", action="store_true",
                    help="exit 1 if anything is contradicted. OFF by default, and "
                         "measured to be a bad idea: swept across 557 curl reports, "
                         "the best threshold on any metric scored Youden J=0.155, "
                         "barely above the 0.0 of a coin flip. Provided for projects "
                         "whose own corpus disagrees.")
    args = ap.parse_args(argv)

    text = sys.stdin.read() if args.report == "-" else Path(args.report).read_text(
        encoding="utf-8", errors="replace")

    claims = extract(text)
    if args.claims_only:
        for c in claims:
            print(f"{c.kind:9s} {c.value[:80]}"
                  + (f"   {c.extra}" if c.extra else ""))
        print(f"\n{len(claims)} claims: {summarise(claims)}", file=sys.stderr)
        return 0

    if not args.repo:
        print("error: --repo is required unless --claims-only is given", file=sys.stderr)
        return 2

    tree = Tree(args.repo, args.ref)
    commit = tree.resolve_ref()
    if commit is None:
        print(f"error: cannot resolve ref '{args.ref}' in {args.repo}", file=sys.stderr)
        return 2

    findings = run(tree, claims)
    meta = {
        "repo": args.repo, "ref": args.ref, "commit": commit,
        "report": args.report, "claims": len(claims),
    }

    print(to_json(findings, meta) if args.json else to_text(findings, meta, args.all))

    # The exit code reports whether THE TOOL ran, not whether the report is
    # suspect. That changed on evidence, not taste.
    #
    # Swept across 557 curl reports (126 confirmed vulnerabilities, 49 in
    # curl's published slop archive), over every threshold on contradiction
    # count, contradicted/consistent and contradicted/claims, the best
    # separation reached was Youden J = 0.155. J = 0 is a coin flip. Every
    # operating point with a tolerable false-positive rate is useless:
    #
    #     count            >= 15    genuine FP  6.3%   slop caught  2.0%
    #     contra/claims    >= 0.5   genuine FP  7.9%   slop caught  8.2%
    #
    # Push the false alarms down to something honest and you catch roughly one
    # slop report in twelve. There is no gate to tune; the aggregate signal is
    # not in the data. Individual findings are still worth reading one by one.
    if args.fail_on_contradiction and tally(findings)[CONTRADICTED]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
