#!/usr/bin/env python
"""Apply the shared labeling engine to a canonical parquet and report classes.

    python scripts/label.py --dataset cicids2017 --tool nfstream --capture Tuesday

Writes a labeled parquet under <data_root>/labeled/<dataset>/<tool>/<capture>.parquet
and prints the per-class flow distribution (with label_confidence breakdown).
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from nids_xstudy import canonical as C
from nids_xstudy import config as cfg
from nids_xstudy.labeling import LabelRules, class_distribution, label_flows

pd.set_option("display.width", 160)
pd.set_option("display.max_columns", 30)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--tool", required=True)
    ap.add_argument("--capture", required=True)
    ap.add_argument("--canonical", default=None, help="explicit canonical parquet path")
    ap.add_argument("--rules", default=None, help="explicit rules.yaml path")
    args = ap.parse_args(argv)

    canon = Path(args.canonical) if args.canonical else \
        cfg.canonical_dir(args.dataset, args.tool) / f"{args.capture}.parquet"
    rules_path = Path(args.rules) if args.rules else cfg.rules_path(args.dataset)

    df = C.read(canon)
    rules = LabelRules.load(rules_path)
    labeled = label_flows(df, rules)

    out = cfg.labeled_dir(args.dataset, args.tool) / f"{args.capture}.parquet"
    labeled.to_parquet(out, engine="pyarrow", index=False)

    dist = class_distribution(labeled)
    print(f"\n=== {args.tool} / {args.dataset} / {args.capture} : {len(labeled):,} flows ===")
    print(dist.to_string(index=False))
    n_attack = int((labeled["binary_label"] == "ATTACK").sum())
    print(f"\nattack flows: {n_attack:,}  ({n_attack/len(labeled)*100:.3f}%)")
    print(f"multi-rule-match flows: {int((labeled['n_rule_matches'] > 1).sum()):,}")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
