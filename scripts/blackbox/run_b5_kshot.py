#!/usr/bin/env python
"""Phase B5.1: k-shot label-efficiency curves. For k in {1,5,10,50,100} labeled
flows per class, train a LogReg head on each extractor's embeddings and evaluate
macro-F1 on a FIXED held-out test set. The k-shot train indices and the test set
are shared across extractors (rows are aligned), so the comparison is on
identical flows -- the honest 'few-shot advantage' test (do NFM embeddings need
fewer labels than hand-engineered features?).

    python scripts/blackbox/run_b5_kshot.py     # nids-xstudy env
-> results/metrics_bb/b5_kshot.csv
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import f1_score  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.ml.dataset import split_mask  # noqa: E402
from nids_xstudy.ml.models import make_pipeline  # noqa: E402
from run_b2_grid import load_nfm  # noqa: E402

EXTRACTORS = ["raw-cnn", "yatc", "etbert", "netfound",
              "nfstream-common", "nfstream-native"]
K_VALUES = [1, 5, 10, 50, 100]
SEEDS = [0, 1, 2, 3, 4]


def labels_and_caps(dataset="cicids2017"):
    sdir = cfg.assembled_dir(dataset, "sample")
    ym, caps = [], []
    for cap in cfg.captures(dataset):
        m = pd.read_parquet(sdir / f"{cap}.meta.parquet")
        ym.append(m["label"].astype("string").fillna("BENIGN").to_numpy())
        caps.append(np.full(len(m), cap))
    return np.concatenate(ym), np.concatenate(caps)


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args()
    ds = args.dataset
    ym, caps = labels_and_caps(ds)
    dfcap = pd.DataFrame({"_capture": caps})
    tr_pool, te = split_mask(dfcap, ym, "stratified", 999, dataset=ds)  # fixed 70/30, rare-safe
    te_idx = np.where(te)[0]
    pool_idx = np.where(tr_pool)[0]
    classes = sorted(set(ym[pool_idx].tolist()))
    by_cls = {c: pool_idx[ym[pool_idx] == c] for c in classes}

    # shared k-shot train index sets
    shots = {}
    for k in K_VALUES:
        for seed in SEEDS:
            rng = np.random.default_rng(1000 * k + seed)
            sel = []
            for c in classes:
                idx = by_cls[c]
                sel.append(idx if len(idx) <= k else rng.choice(idx, k, replace=False))
            shots[(k, seed)] = np.concatenate(sel)

    rows = []
    for model in EXTRACTORS:
        X = load_nfm(model, ds)[0]
        yte = ym[te_idx]
        for (k, seed), sel in shots.items():
            pipe = make_pipeline("logreg", seed).fit(X[sel], ym[sel])
            pred = pipe.predict(X[te_idx])
            rows.append({"extractor": model, "k": k, "seed": seed,
                         "n_train": int(len(sel)),
                         "macro_f1": float(f1_score(yte, pred, average="macro", zero_division=0))})
        m = np.mean([r["macro_f1"] for r in rows if r["extractor"] == model and r["k"] == 100])
        print(f"[ok] {model}: k=100 macro-F1={m:.3f}", flush=True)
    out = cfg.results_dir() / "metrics_bb" / ds / "b5_kshot.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(out, index=False)
    print(f"wrote {out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
