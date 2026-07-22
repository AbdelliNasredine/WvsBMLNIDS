#!/usr/bin/env python
"""Cross-tool flow-count comparison per capture (a lightweight RQ3 preview).

Not the full Phase-2 flow alignment (no per-flow matching) — just total flow
counts per tool per capture, which already exposes tool-induced divergence and
its concentration in attack-heavy days.

    python scripts/flow_count_compare.py --dataset cicids2017
"""
from __future__ import annotations

import argparse

import pandas as pd

from nids_xstudy import canonical as C
from nids_xstudy import config as cfg

KNOWN_TOOLS = ["nfstream", "zeek", "cicflowmeter-orig", "cicflowmeter-fixed",
               "argus", "tranalyzer"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    ap.add_argument("--ref", default="nfstream", help="reference tool for ratios")
    args = ap.parse_args(argv)

    caps = cfg.captures(args.dataset)
    rows = []
    tools_present = []
    for tool in KNOWN_TOOLS:
        d = cfg.canonical_dir(args.dataset, tool)
        if any((d / f"{c}.parquet").exists() for c in caps):
            tools_present.append(tool)

    counts = {tool: {} for tool in tools_present}
    for tool in tools_present:
        for cap in caps:
            p = cfg.canonical_dir(args.dataset, tool) / f"{cap}.parquet"
            counts[tool][cap] = len(C.read(p)) if p.exists() else None

    for cap in caps:
        row = {"capture": cap}
        for tool in tools_present:
            row[tool] = counts[tool].get(cap)
        rows.append(row)
    df = pd.DataFrame(rows)

    # ratio columns vs reference
    ref = args.ref if args.ref in tools_present else tools_present[0]
    ratio_cols = []
    for tool in tools_present:
        if tool == ref:
            continue
        col = f"{tool}/{ref}"
        df[col] = (df[tool] / df[ref]).round(3)
        ratio_cols.append(col)

    def md_table(d: pd.DataFrame) -> str:
        head = "| " + " | ".join(d.columns) + " |"
        sep = "| " + " | ".join("---" for _ in d.columns) + " |"
        body = ["| " + " | ".join("" if pd.isna(v) else str(v) for v in r) + " |"
                for r in d.itertuples(index=False)]
        return "\n".join([head, sep, *body])

    md = [f"# Cross-tool flow counts — {args.dataset}", "",
          f"Total flows per capture per extractor (reference = {ref}). Ratios far",
          "from 1 indicate flow-accounting divergence; expect the largest",
          "divergence on attack-heavy captures (RQ3 / H3).", "",
          md_table(df), ""]
    tables = cfg.results_dir() / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    out = tables / f"flow_counts_{args.dataset}.md"
    out.write_text("\n".join(md) + "\n", encoding="utf-8")

    print(df.to_string(index=False))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
