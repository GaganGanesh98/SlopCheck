"""Render the evidence transcript.

There is no score and no classification. The output is a list of claims the
report made and what the source tree says about each. A maintainer reads the
CONTRADICTED lines and decides. That is the whole design.
"""
from __future__ import annotations

import json
from .checks import Finding, CONTRADICTED, CONSISTENT, UNCHECKABLE

ORDER = {CONTRADICTED: 0, CONSISTENT: 1, UNCHECKABLE: 2}
MARK = {CONTRADICTED: "[X]", CONSISTENT: "[ok]", UNCHECKABLE: "[?]"}


def tally(findings: list[Finding]) -> dict[str, int]:
    t = {CONTRADICTED: 0, CONSISTENT: 0, UNCHECKABLE: 0}
    for f in findings:
        t[f.verdict] = t.get(f.verdict, 0) + 1
    return t


def to_json(findings: list[Finding], meta: dict) -> str:
    return json.dumps(
        {"meta": meta, "tally": tally(findings),
         "findings": [f.to_dict() for f in findings]},
        indent=2,
    )


def to_text(findings: list[Finding], meta: dict, show_all: bool = False) -> str:
    t = tally(findings)
    L: list[str] = []
    L.append("slopcheck grounding report")
    L.append(f"  repository : {meta.get('repo')}")
    L.append(f"  ref        : {meta.get('ref')}  ({meta.get('commit', '?')[:12]})")
    L.append(f"  report     : {meta.get('report')}")
    L.append("")
    L.append(f"  {t[CONTRADICTED]} contradicted   "
             f"{t[CONSISTENT]} consistent   {t[UNCHECKABLE]} uncheckable")
    L.append("")

    if t[CONTRADICTED] == 0:
        L.append("  Nothing in this report is contradicted by the source tree.")
        L.append("  That is not evidence the bug is real -- only that the static")
        L.append("  claims hold up. Reproduction is still required.")
        L.append("")

    groups = sorted(findings, key=lambda f: (ORDER[f.verdict], f.claim_kind))
    shown = groups if show_all else [f for f in groups if f.verdict != CONSISTENT]

    current = None
    for f in shown:
        if f.verdict != current:
            current = f.verdict
            L.append(f"--- {current} " + "-" * (56 - len(current)))
        L.append(f"{MARK[f.verdict]} {f.claim_kind}: {f.claim_value}")
        L.append(f"     check    : {f.check}")
        L.append(f"     observed : {f.observed}")
        if f.context:
            L.append(f"     in report: \"{f.context[:110]}\"")
        L.append("")

    if not show_all and t[CONSISTENT]:
        L.append(f"({t[CONSISTENT]} consistent claims hidden; pass --all to see them)")
        L.append("")

    L.append("This tool checks only whether a report's stated facts match the source")
    L.append("tree. It does not execute code, does not judge intent, and cannot tell")
    L.append("you whether a vulnerability exists. A human decides.")
    return "\n".join(L)
