#!/usr/bin/env python
"""Label all captures for a tool and validate per-class counts vs corrected refs.

Labels every canonical capture of a dataset/tool, writes labeled parquets, then
aggregates per-class flow counts across the week and compares them to the
Engelen/Liu corrected *effective* counts (data/labels/cicids2017/expected_counts.md).

    python scripts/validate_labels.py --dataset cicids2017 --tool nfstream

Our counts are the OUTER-window counts (effective + attempted + minor benign
spillover) and use a different flow segmenter than CICFlowMeter, so exact
agreement is not expected — the check is order-of-magnitude + timezone sanity
(e.g. Heartbleed must be ~11 flows; a 3-hour timezone error would zero it out).
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from nids_xstudy import canonical as C
from nids_xstudy import config as cfg
from nids_xstudy.labeling import LabelRules, label_flows

# Engelen WTMC2021 Table I "effective" counts (see expected_counts.md).
EXPECTED_EFFECTIVE = {
    "FTP-Patator": 3973, "SSH-Patator": 2980,
    "DoS GoldenEye": 7567, "DoS Hulk": 158469,
    "DoS Slowhttptest": 1742, "DoS slowloris": 4001,
    "Heartbleed": 11,
    "Web Attack - Brute Force": 151, "Web Attack - XSS": 27,
    "Web Attack - Sql Injection": 12,
    "Infiltration": 32, "Bot": 738,
    "PortScan": 159023, "DDoS": 95123,
}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    ap.add_argument("--tool", default="nfstream")
    args = ap.parse_args(argv)

    rules = LabelRules.load(cfg.rules_path(args.dataset))
    per_capture = {}
    totals = pd.Series(dtype="int64")
    total_flows = 0

    for cap in cfg.captures(args.dataset):
        canon = cfg.canonical_dir(args.dataset, args.tool) / f"{cap}.parquet"
        if not canon.exists():
            print(f"[skip] {cap}: no canonical parquet")
            continue
        df = label_flows(C.read(canon), rules)
        out = cfg.labeled_dir(args.dataset, args.tool) / f"{cap}.parquet"
        df.to_parquet(out, engine="pyarrow", index=False)
        counts = df["label"].value_counts()
        per_capture[cap] = counts
        totals = totals.add(counts, fill_value=0)
        total_flows += len(df)
        print(f"[ok] {cap}: {len(df):,} flows, {int((df.binary_label=='ATTACK').sum()):,} attack")

    totals = totals.astype("int64")

    # Build comparison table
    rows = []
    for label, exp in EXPECTED_EFFECTIVE.items():
        got = int(totals.get(label, 0))
        ratio = got / exp if exp else float("nan")
        rows.append({"class": label, "ours": got, "expected_effective": exp,
                     "ratio": round(ratio, 3)})
    cmp = pd.DataFrame(rows).sort_values("expected_effective", ascending=False)
    benign = int(totals.get(rules.benign_label, 0))

    def md_table(df: pd.DataFrame) -> str:
        head = "| " + " | ".join(df.columns) + " |"
        sep = "| " + " | ".join("---" for _ in df.columns) + " |"
        body = ["| " + " | ".join(str(v) for v in r) + " |"
                for r in df.itertuples(index=False)]
        return "\n".join([head, sep, *body])

    md = ["# CICIDS2017 label validation — %s" % args.tool, "",
          f"Total flows (week): **{total_flows:,}**  |  BENIGN: **{benign:,}**  |  "
          f"attack classes: {len(EXPECTED_EFFECTIVE)}", "",
          "Ours = outer-window count (this tool's segmentation). Expected = Engelen",
          "WTMC2021 effective (CICFlowMeter-fixed). Ratio≈1 ⇒ agreement; large",
          "deviations are expected for attempted-heavy classes (Web/Bot/Slow*).", "",
          md_table(cmp), "",
          "## Per-capture attack labels", ""]
    for cap, counts in per_capture.items():
        atk = counts[[i for i in counts.index if i != rules.benign_label]]
        if len(atk):
            md.append(f"**{cap}**: " + ", ".join(f"{k}={int(v)}" for k, v in atk.items()))
    report = "\n".join(md) + "\n"

    tables = cfg.results_dir() / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    rpt_path = tables / f"label_counts_{args.tool}.md"
    rpt_path.write_text(report, encoding="utf-8")

    print("\n" + cmp.to_string(index=False))
    print(f"\nBENIGN: {benign:,} | total: {total_flows:,}")
    print(f"wrote {rpt_path}")


if __name__ == "__main__":
    main()
