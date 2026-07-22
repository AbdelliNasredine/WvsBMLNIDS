#!/usr/bin/env python
"""Consolidated cross-tool attack-count matrix (Phase-1 / RQ3-RQ4 preview).

Aggregates each tool's labeled flows (across whatever captures are present) into
one class x tool matrix, so the divergence in attack-flow counts across
extractors is visible at a glance. Tools with only some captures labeled are
included with a note.

    python scripts/attack_counts_by_tool.py --dataset cicids2017
"""
from __future__ import annotations

import argparse

import pandas as pd

from nids_xstudy import config as cfg

TOOLS = ["nfstream", "zeek", "tranalyzer", "cicflowmeter-orig", "cicflowmeter-fixed",
         "argus", "go-flows", "yaf", "joy"]

CLASS_ORDER = [
    "BENIGN", "PortScan", "DoS Hulk", "DDoS", "DoS GoldenEye", "DoS slowloris",
    "DoS Slowhttptest", "FTP-Patator", "SSH-Patator", "Bot",
    "Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - Sql Injection",
    "Infiltration", "Heartbleed",
]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args(argv)

    per_tool_counts = {}
    per_tool_caps = {}
    for tool in TOOLS:
        d = cfg.labeled_dir(args.dataset, tool)
        parquets = sorted(d.glob("*.parquet"))
        if not parquets:
            continue
        counts = pd.Series(dtype="int64")
        caps = []
        for p in parquets:
            df = pd.read_parquet(p, columns=["label"])
            counts = counts.add(df["label"].value_counts(), fill_value=0)
            caps.append(p.stem)
        per_tool_counts[tool] = counts.astype("int64")
        per_tool_caps[tool] = caps

    if not per_tool_counts:
        print("no labeled parquets found — label tools first (scripts/validate_labels.py)")
        return

    tools = list(per_tool_counts)
    labels = [c for c in CLASS_ORDER if any(c in per_tool_counts[t].index for t in tools)]
    # include any unexpected labels at the end
    for t in tools:
        for lab in per_tool_counts[t].index:
            if lab not in labels:
                labels.append(lab)

    rows = []
    for lab in labels:
        row = {"class": lab}
        for t in tools:
            row[t] = int(per_tool_counts[t].get(lab, 0))
        rows.append(row)
    mat = pd.DataFrame(rows)

    def md(df: pd.DataFrame) -> str:
        head = "| " + " | ".join(df.columns) + " |"
        sep = "| " + " | ".join("---" for _ in df.columns) + " |"
        body = ["| " + " | ".join(f"{v:,}" if isinstance(v, int) else str(v)
                                  for v in r) + " |"
                for r in df.itertuples(index=False)]
        return "\n".join([head, sep, *body])

    lines = [f"# CICIDS2017 attack-flow counts by extractor", "",
             "Flows per class per tool (summed over the captures each tool has",
             "labeled so far). Divergence across columns is the RQ3/RQ4 signal —",
             "note e.g. DoS Hulk (NFStream merges; others match CICFlowMeter) and",
             "the CICFlowMeter orig-vs-fixed delta.", "",
             "Captures labeled per tool:", ""]
    for t in tools:
        n = len(per_tool_caps[t])
        lines.append(f"- **{t}**: {n}/5 days ({', '.join(per_tool_caps[t])})")
    lines += ["", md(mat), ""]

    out = cfg.results_dir() / "tables" / f"attack_counts_by_tool_{args.dataset}.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(mat.to_string(index=False))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
