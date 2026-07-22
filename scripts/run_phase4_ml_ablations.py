#!/usr/bin/env python
"""Phase-4b ML ablations (no re-extraction): dst_port shortcut + label-noise.

* port      : add dst_port to R-common (shortcut-learning check) — compare to
              the main-grid R-common baseline.
* labelnoise: drop window_edge (ambiguous) flows, keep label_confidence in
              {exact, benign}, then re-fit.

Runs a representative slice (R-common, RF+XGB, multiclass/stratified +
binary/temporal, 3 seeds) into results/ablations/. Resumable.
"""
from __future__ import annotations

import argparse
import itertools

from nids_xstudy import config as cfg
from nids_xstudy.ml import dataset as D
from nids_xstudy.ml.train import run

TOOLS = ["nfstream", "zeek", "tranalyzer", "cicflowmeter-orig", "cicflowmeter-fixed",
         "argus", "go-flows", "yaf", "joy"]
CELLS = [("multiclass", "stratified"), ("binary", "temporal")]
MODELS = ["rf", "xgb"]
SEEDS = [0, 1, 2]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ablations", nargs="+", default=["port", "labelnoise"],
                    choices=["port", "labelnoise"])
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args(argv)
    ds = args.dataset
    ABL = cfg.results_dir() / "ablations" / ds

    for tool in TOOLS:
        df = D.load_tool(tool, ds)
        df_exact = df[df["label_confidence"].astype("string") != "window_edge"] \
            if "labelnoise" in args.ablations else None
        for model, (task, split), seed in itertools.product(MODELS, CELLS, SEEDS):
            base = f"{tool}__common__{model}__{task}__{split}__s{seed}"
            if "port" in args.ablations and not (ABL / "port" / f"{base}__port.json").exists():
                run(tool, "common", model, task, split, seed, dataset=ds, df=df, include_port=True,
                    max_train=400000, metrics_dir=ABL / "port", tag="port")
                print(f"[ok] port {base}", flush=True)
            if "labelnoise" in args.ablations and not (ABL / "exact" / f"{base}__exact.json").exists():
                run(tool, "common", model, task, split, seed, dataset=ds, df=df_exact,
                    max_train=400000, metrics_dir=ABL / "exact", tag="exact")
                print(f"[ok] exact {base}", flush=True)
    print("ML ABLATIONS DONE", flush=True)


if __name__ == "__main__":
    main()
