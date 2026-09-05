#!/usr/bin/env python3
"""Build a labelled corpus of curl vulnerability reports from HackerOne.

Why this exists
---------------
slopcheck's published results rest on six hand-picked reports. That is a demo,
not evidence. curl has hundreds of publicly disclosed reports carrying the
maintainers' own verdicts, and the maintainers separately publish an archive of
reports they rejected as AI slop. Together those give a labelled evaluation set.
Nobody had assembled it.

Labels, weakest to strongest
----------------------------
  substate            HackerOne's own outcome: resolved / not-applicable /
                      informative / duplicate / spam. Note that not-applicable
                      does NOT mean slop -- plenty of honest, out-of-scope
                      reports land there. Use it as a weak label only.
  slop_archive        Membership in curl's published AI-slop gist. This is the
                      gold negative label, and it is small (~49 reports).
  resolved            A confirmed vulnerability. The gold positive label.

Politeness
----------
Paginated GraphQL, one request per page rather than one per report, with a
delay between pages and a descriptive User-Agent. Default settings issue roughly
25 requests for the whole corpus. Do not remove the delay.

Usage
-----
    python3 tools/fetch_curl_corpus.py --out data/curl
    python3 tools/fetch_curl_corpus.py --handle nodejs --out data/nodejs
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

GRAPHQL = "https://hackerone.com/graphql"
SLOP_GIST = ("https://gist.githubusercontent.com/bagder/"
             "07f7581f6e3d78ef37dfbfc81fd1d1cd/raw")
UA = ("slopcheck-dataset-research/0.1 "
      "(+https://github.com/GaganGanesh98/SlopCheck)")

QUERY = """
query($handle: String!, $first: Int!, $after: String) {
  reports(handle: $handle, first: $first, after: $after) {
    pageInfo { hasNextPage endCursor }
    edges { node {
      _id
      title
      substate
      state
      url
      created_at
      disclosed_at
      cve_ids
    } }
  }
}
"""


def post(query: str, variables: dict, retries: int = 4) -> dict:
    body = json.dumps({"query": query, "variables": variables}).encode()
    for attempt in range(retries):
        req = urllib.request.Request(
            GRAPHQL, data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "Accept": "application/json", "User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                payload = json.loads(r.read())
            if "errors" in payload:
                raise RuntimeError(payload["errors"][0].get("message", "graphql error"))
            return payload
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            wait = 5 * (attempt + 1)
            print(f"  transient error ({e}); backing off {wait}s", file=sys.stderr)
            time.sleep(wait)
    raise RuntimeError("gave up after retries")


def fetch_body(rid: int, retries: int = 3) -> dict | None:
    """Per-report JSON. GraphQL's connection omits the body, so this is the
    only source for report text -- one request each, hence the delay."""
    url = f"https://hackerone.com/reports/{rid}.json"
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": UA, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code in (403, 404, 410):
                return None                      # withdrawn or access-limited
            time.sleep(5 * (attempt + 1))
        except (urllib.error.URLError, TimeoutError):
            time.sleep(5 * (attempt + 1))
    return None


def fetch_slop_ids() -> set[int]:
    """Report IDs from curl's published AI-slop archive."""
    req = urllib.request.Request(SLOP_GIST, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            text = r.read().decode("utf-8", "replace")
    except Exception as e:
        print(f"warning: could not fetch slop archive ({e}); "
              f"gold negative labels will be missing", file=sys.stderr)
        return set()
    return {int(m) for m in re.findall(r"hackerone\.com/reports/(\d+)", text)}


def fetch_reports(handle: str, page_size: int, delay: float,
                  limit: int | None) -> list[dict]:
    out: list[dict] = []
    cursor = None
    page = 0
    while True:
        page += 1
        data = post(QUERY, {"handle": handle, "first": page_size, "after": cursor})
        conn = data["data"]["reports"]
        nodes = [e["node"] for e in conn["edges"]]
        out.extend(nodes)
        print(f"  page {page:>3}  +{len(nodes):>3}  total {len(out)}", file=sys.stderr)
        if limit and len(out) >= limit:
            return out[:limit]
        if not conn["pageInfo"]["hasNextPage"]:
            return out
        cursor = conn["pageInfo"]["endCursor"]
        time.sleep(delay)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--handle", default="curl", help="HackerOne program handle")
    ap.add_argument("--out", default="data/curl", help="output directory")
    ap.add_argument("--page-size", type=int, default=25)
    ap.add_argument("--delay", type=float, default=1.5, help="seconds between pages")
    ap.add_argument("--body-delay", type=float, default=1.0,
                    help="seconds between per-report body fetches; do not lower")
    ap.add_argument("--limit", type=int, default=None, help="stop after N reports")
    args = ap.parse_args()

    outdir = Path(args.out)
    (outdir / "reports").mkdir(parents=True, exist_ok=True)

    print(f"fetching slop archive...", file=sys.stderr)
    slop = fetch_slop_ids()
    print(f"  {len(slop)} report ids in the archive", file=sys.stderr)

    print(f"fetching disclosed reports for '{args.handle}'...", file=sys.stderr)
    nodes = fetch_reports(args.handle, args.page_size, args.delay, args.limit)

    # The listing may not surface every archived report. The slop IDs are the
    # gold negative labels, so fetch any the listing missed rather than
    # silently shipping a corpus with holes in its most valuable class.
    listed = {int(n["_id"]) for n in nodes}
    for rid in sorted(slop - listed):
        nodes.append({"_id": rid, "title": None, "substate": None, "state": None,
                      "url": f"https://hackerone.com/reports/{rid}",
                      "created_at": None, "disclosed_at": None, "cve_ids": None,
                      "_from_archive_only": True})
    if len(nodes) > len(listed):
        print(f"  +{len(nodes) - len(listed)} archive reports absent from the listing",
              file=sys.stderr)

    print(f"fetching {len(nodes)} report bodies "
          f"(~{len(nodes) * args.body_delay / 60:.0f} min, resumable)...",
          file=sys.stderr)
    index = []
    for i, n in enumerate(nodes, 1):
        rid = int(n["_id"])
        dest = outdir / "reports" / f"{rid}.txt"
        if dest.exists():                        # resume: never refetch
            body = dest.read_text(encoding="utf-8").split("\n\n", 1)[-1]
        else:
            doc = fetch_body(rid)
            body = (doc or {}).get("vulnerability_information") or ""
            if doc and n.get("_from_archive_only"):
                n["title"] = doc.get("title")
                n["substate"] = doc.get("substate")
                n["state"] = doc.get("state")
                n["created_at"] = doc.get("created_at")
                n["disclosed_at"] = doc.get("disclosed_at")
            dest.write_text((n.get("title") or "") + "\n\n" + body, encoding="utf-8")
            time.sleep(args.body_delay)
        if i % 25 == 0 or i == len(nodes):
            print(f"  {i}/{len(nodes)}", file=sys.stderr)
        index.append({
            "id": rid,
            "title": n.get("title"),
            "substate": n.get("substate"),
            "state": n.get("state"),
            "url": n.get("url"),
            "created_at": n.get("created_at"),
            "disclosed_at": n.get("disclosed_at"),
            "cve_ids": n.get("cve_ids"),
            "body_chars": len(body),
            "in_slop_archive": rid in slop,
            "label": ("slop" if rid in slop
                      else "vuln" if n.get("substate") == "resolved"
                      else "unlabelled"),
        })

    index.sort(key=lambda r: r["id"])
    (outdir / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")

    with (outdir / "index.csv").open("w", encoding="utf-8") as fh:
        cols = ["id", "label", "substate", "in_slop_archive", "body_chars",
                "cve_ids", "created_at", "title"]
        fh.write(",".join(cols) + "\n")
        for r in index:
            row = [str(r.get(c, "")).replace('"', "'") for c in cols]
            fh.write(",".join(f'"{v}"' for v in row) + "\n")

    by_label: dict[str, int] = {}
    by_sub: dict[str, int] = {}
    empty = 0
    for r in index:
        by_label[r["label"]] = by_label.get(r["label"], 0) + 1
        by_sub[r["substate"] or "?"] = by_sub.get(r["substate"] or "?", 0) + 1
        if r["body_chars"] == 0:
            empty += 1

    missing = sorted(slop - {r["id"] for r in index})

    print(f"\n{len(index)} reports -> {outdir}")
    print(f"  labels    : {by_label}")
    print(f"  substates : {by_sub}")
    print(f"  empty body: {empty}")
    if missing:
        print(f"  in archive but not in listing: {len(missing)} {missing[:6]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
