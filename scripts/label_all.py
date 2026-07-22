#!/usr/bin/env python
"""Batch-label every (tool, capture) canonical parquet for a dataset.

Applies the shared traffic-level engine + (for dapt20) the hybrid recon
projection via nids_xstudy.labeling.label_dataset, capture-scoped. Resumable
(skips captures already labeled unless --force). Prints a per-tool attack summary.

    python scripts/label_all.py --dataset dapt20
    python scripts/label_all.py --dataset dapt20 --tools nfstream zeek --force
"""
from __future__ import annotations

import argparse
from pathlib import Path

from nids_xstudy import canonical as C
from nids_xstudy import config as cfg
from nids_xstudy.labeling import label_dataset

TOOLS = ["nfstream", "zeek", "tranalyzer", "cicflowmeter-orig", "cicflowmeter-fixed",
         "argus", "go-flows", "yaf", "joy"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--tools", nargs="+", default=TOOLS)
    ap.add_argument("--captures", nargs="+", default=None)
    ap.add_argument("--force", action="store_true", help="relabel even if output exists")
    args = ap.parse_args(argv)

    caps = args.captures or cfg.captures(args.dataset)
    ok = skip = miss = 0
    for tool in args.tools:
        n_attack = n_flows = 0
        for cap in caps:
            canon = cfg.canonical_dir(args.dataset, tool) / f"{cap}.parquet"
            if not canon.exists():
                miss += 1
                continue
            out = cfg.labeled_dir(args.dataset, tool) / f"{cap}.parquet"
            if out.exists() and not args.force:
                skip += 1
                import pandas as pd
                lab = pd.read_parquet(out, columns=["binary_label"])
            else:
                df = C.read(canon)
                lab = label_dataset(df, args.dataset, cfg, capture=cap)
                lab.to_parquet(out, engine="pyarrow", index=False)
                ok += 1
            n_flows += len(lab)
            n_attack += int((lab["binary_label"].astype("string") == "ATTACK").sum())
        if n_flows:
            print(f"[{tool}] {n_flows:,} flows, {n_attack:,} attack "
                  f"({n_attack/n_flows*100:.2f}%)", flush=True)
    print(f"DONE dataset={args.dataset}: {ok} labeled, {skip} skipped, {miss} missing-canonical",
          flush=True)


if __name__ == "__main__":
    main()
