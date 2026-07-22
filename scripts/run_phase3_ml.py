#!/usr/bin/env python
"""Phase-3 driver: run the ML grid (tool x regime x model x task x split x seed).

Loads each tool's flows once (reused across all its combos). Training is capped
at --max-train rows (stratified) so the full grid is feasible. Temporal +
multiclass is skipped (train/test captures share no attack classes, for both
CICIDS2017 and DAPT20). Metrics land in results/metrics/<dataset>/. Resumable
(skips existing metrics JSON) and fault-tolerant.

    python scripts/run_phase3_ml.py
    python scripts/run_phase3_ml.py --dataset dapt20 --tools nfstream --models rf --seeds 0
"""
from __future__ import annotations

import argparse
import itertools
import time
import traceback

from nids_xstudy import config as cfg
from nids_xstudy.ml import dataset as D
from nids_xstudy.ml.train import run

TOOLS = ["nfstream", "zeek", "tranalyzer", "cicflowmeter-orig", "cicflowmeter-fixed",
         "argus", "go-flows", "yaf", "joy"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tools", nargs="+", default=TOOLS)
    ap.add_argument("--regimes", nargs="+", default=["common", "native"])
    ap.add_argument("--models", nargs="+", default=["rf", "xgb", "logreg", "mlp"])
    ap.add_argument("--tasks", nargs="+", default=["binary", "multiclass"])
    ap.add_argument("--splits", nargs="+", default=["stratified", "temporal"])
    ap.add_argument("--seeds", nargs="+", type=int, default=[0, 1, 2, 3, 4])
    ap.add_argument("--max-train", type=int, default=400000)
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args(argv)

    mdir = cfg.results_dir() / "metrics" / args.dataset
    mdir.mkdir(parents=True, exist_ok=True)
    ok = fail = skip = 0
    for tool in args.tools:
        combos = [c for c in itertools.product(args.regimes, args.models, args.tasks,
                                               args.splits, args.seeds)
                  if not (c[2] == "multiclass" and c[3] == "temporal")]
        # anything left to do for this tool?
        todo = [c for c in combos
                if not (mdir / f"{tool}__{c[0]}__{c[1]}__{c[2]}__{c[3]}__s{c[4]}.json").exists()]
        if not todo:
            skip += len(combos)
            continue
        df = D.load_tool(tool, args.dataset)  # load once per tool
        for regime, model, task, split, seed in combos:
            name = f"{tool}__{regime}__{model}__{task}__{split}__s{seed}.json"
            if (mdir / name).exists():
                skip += 1
                continue
            t0 = time.time()
            try:
                r = run(tool, regime, model, task, split, seed, dataset=args.dataset,
                        df=df, max_train=args.max_train, metrics_dir=mdir)
                print(f"[ok] {name[:-5]}: macroF1={r['metrics']['macro_f1']:.4f} "
                      f"({time.time()-t0:.0f}s)", flush=True)
                ok += 1
            except Exception as e:  # noqa: BLE001
                print(f"[FAIL] {name[:-5]}: {e}", flush=True)
                traceback.print_exc()
                fail += 1
    print(f"DONE: {ok} ok, {fail} failed, {skip} skipped", flush=True)


if __name__ == "__main__":
    main()
