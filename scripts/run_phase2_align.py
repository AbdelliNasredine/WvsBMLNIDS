#!/usr/bin/env python
"""Phase-2 driver: cross-tool flow-alignment over the ordered tool-pair grid.

For every ordered pair (A, B) and capture day, match A's flows against B's and
record per-class 1:1 / split / merge / unmatched counts. Resumable (skips
(day, A, B) already recorded) and incremental (appends to a CSV) so partial
results are usable and figures can be regenerated without re-matching.

    python scripts/run_phase2_align.py                 # all pairs, all days
    python scripts/run_phase2_align.py --days Wednesday --tools nfstream zeek cicflowmeter-fixed
"""
from __future__ import annotations

import argparse
import csv
import itertools
import time
from pathlib import Path

import pandas as pd

from nids_xstudy import config as cfg
from nids_xstudy.flow_alignment.align import CATEGORIES, category_summary, match_pair

TOOLS = ["nfstream", "zeek", "tranalyzer", "cicflowmeter-orig", "cicflowmeter-fixed",
         "argus", "go-flows", "yaf", "joy"]
COLS = ["src_ip", "src_port", "dst_ip", "dst_port", "proto", "t_start", "t_end", "label"]
FIELDS = ["day", "tool_a", "tool_b", "class", "n", "c_1to1", "c_split", "c_merge", "c_unmatched"]


def _out_path(dataset):
    return cfg.results_dir() / "phase2" / dataset / "categories.csv"


def _load_day(day, tools, dataset):
    frames = {}
    for t in tools:
        p = cfg.labeled_dir(dataset, t) / f"{day}.parquet"
        if p.exists():
            frames[t] = pd.read_parquet(p, columns=COLS)
    return frames


def _done_set(out):
    if not out.exists():
        return set()
    df = pd.read_csv(out, usecols=["day", "tool_a", "tool_b"])
    return set(map(tuple, df.drop_duplicates().to_numpy()))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tools", nargs="+", default=TOOLS)
    ap.add_argument("--days", nargs="+", default=None)
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args(argv)
    days = args.days or cfg.captures(args.dataset)

    OUT = _out_path(args.dataset)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    done = _done_set(OUT)
    new_file = not OUT.exists()
    fh = open(OUT, "a", newline="", encoding="utf-8")
    w = csv.DictWriter(fh, fieldnames=FIELDS)
    if new_file:
        w.writeheader()

    for day in days:
        frames = _load_day(day, args.tools, args.dataset)
        present = [t for t in args.tools if t in frames]
        for a, b in itertools.permutations(present, 2):
            if (day, a, b) in done:
                continue
            t0 = time.time()
            a_cat, _ = match_pair(frames[a], frames[b])
            summ = category_summary(a_cat)
            for _, r in summ.iterrows():
                w.writerow({"day": day, "tool_a": a, "tool_b": b, "class": r["class"],
                            "n": int(r["n"]), "c_1to1": int(r["1:1"]),
                            "c_split": int(r["split"]), "c_merge": int(r["merge"]),
                            "c_unmatched": int(r["unmatched"])})
            fh.flush()
            print(f"[{day}] {a} vs {b}: 1:1={summ.iloc[0]['1:1_frac']:.3f} "
                  f"({time.time()-t0:.0f}s)", flush=True)
    fh.close()
    print("PHASE2 ALIGN DONE", flush=True)


if __name__ == "__main__":
    main()
