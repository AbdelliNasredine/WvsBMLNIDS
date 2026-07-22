#!/usr/bin/env python
"""Phase B2.1: frozen black-box evaluation grid. Trains the SAME classical heads
as the white-box study (RF/XGBoost/MLP/LogReg) on each NFM's cached sample
embeddings + the shared labels, under the identical protocol (binary both
splits, multiclass stratified; 5 seeds; same preprocessing + metrics).

Results -> results/metrics_bb/<nfm>__embedding__<head>__<task>__<split>__s<seed>.json
with extractor_family=nfm, so they join the white-box grid for the unified
analysis. CPU only (embeddings precomputed). Run in the nids-xstudy env.
"""
from __future__ import annotations

import argparse
import itertools
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import (average_precision_score, balanced_accuracy_score,  # noqa: E402
                             classification_report, confusion_matrix, f1_score)

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.ml.dataset import split_mask  # noqa: E402
from nids_xstudy.ml.models import make_pipeline  # noqa: E402
from nids_xstudy.extraction.base import config_hash, git_commit  # noqa: E402

NFMS = ["raw-cnn", "yatc", "etbert", "netfound"]
HEADS = ["rf", "xgb", "logreg", "mlp"]


def load_nfm(model, dataset="cicids2017", cfg_name="sample"):
    edir = cfg.embeddings_dir(dataset, model, cfg_name)
    sdir = cfg.assembled_dir(dataset, cfg_name)
    Xs, lab, binlab, caps = [], [], [], []
    for capn in cfg.captures(dataset):
        e = np.load(edir / f"{capn}.npy")
        m = pd.read_parquet(sdir / f"{capn}.meta.parquet")
        if len(e) != len(m):
            raise RuntimeError(f"{model}/{capn}: emb {len(e)} != meta {len(m)}")
        Xs.append(e.astype(np.float32))
        lab.append(m["label"].astype("string").fillna("BENIGN").to_numpy())
        binlab.append((m["binary_label"].astype("string") == "ATTACK").astype(int).to_numpy())
        caps.append(np.full(len(e), capn))
    return (np.concatenate(Xs), np.concatenate(lab), np.concatenate(binlab),
            np.concatenate(caps))


def run(model, head, task, split, seed, X, y_multi, y_bin, cap, outdir, max_train=None,
        dataset="cicids2017"):
    t0 = time.time()
    y_raw = y_bin if task == "binary" else y_multi
    dfcap = pd.DataFrame({"_capture": cap})
    tr, te = split_mask(dfcap, y_raw, split, seed, dataset=dataset)
    if max_train:  # cap high-dim train for memory/time (rare-class safe)
        from nids_xstudy.ml.train import _cap_train
        tr = _cap_train(tr, y_raw, max_train, seed)
    classes = sorted(set(y_raw[tr].tolist()))
    idx = {c: i for i, c in enumerate(classes)}
    phantom = len(classes)
    ytr = np.array([idx[c] for c in y_raw[tr]], dtype=int)
    yte = np.array([idx.get(c, phantom) for c in y_raw[te]], dtype=int)
    names = [str(c) for c in classes] + (["<unseen>"] if (yte == phantom).any() else [])

    pipe = make_pipeline(head, seed).fit(X[tr], ytr)
    pred = pipe.predict(X[te])
    rep = classification_report(yte, pred, labels=list(range(len(names))),
                                target_names=names, output_dict=True, zero_division=0)
    metrics = {
        "macro_f1": float(f1_score(yte, pred, average="macro", labels=list(range(len(classes))), zero_division=0)),
        "weighted_f1": float(f1_score(yte, pred, average="weighted", zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(yte, pred)),
        "per_class": {cn: {k: float(rep[cn][k]) for k in ("precision", "recall", "f1-score", "support")}
                      for cn in names if cn in rep},
    }
    if task == "binary":
        cm = confusion_matrix(yte, pred, labels=[0, 1]); tn, fp, fn, tp = cm.ravel()
        metrics["fpr"] = float(fp / (fp + tn)) if (fp + tn) else 0.0
        metrics["attack_recall"] = float(tp / (tp + fn)) if (tp + fn) else 0.0
        metrics["attack_precision"] = float(tp / (tp + fp)) if (tp + fp) else 0.0
        try:
            metrics["auc_pr"] = float(average_precision_score((yte == 1).astype(int), pipe.predict_proba(X[te])[:, 1]))
        except Exception:
            metrics["auc_pr"] = None
    metrics["confusion_matrix"] = confusion_matrix(yte, pred).tolist()
    metrics["class_order"] = names

    conf = {"tool": model, "regime": "embedding", "model": head, "task": task,
            "split": split, "seed": seed, "dataset": dataset,
            "n_features": int(X.shape[1]), "extractor_family": "nfm", "cfg_name": "sample",
            "max_train": max_train}
    rec = {"config": conf, "config_hash": config_hash(conf), "git_commit": git_commit(),
           "n_train": int(tr.sum()), "n_test": int(te.sum()), "metrics": metrics,
           "wall_seconds": round(time.time() - t0, 1)}
    name = f"{model}__embedding__{head}__{task}__{split}__s{seed}.json"
    (outdir / name).write_text(json.dumps(rec, indent=2), encoding="utf-8")
    return metrics["macro_f1"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--models", nargs="+", default=NFMS)
    ap.add_argument("--heads", nargs="+", default=HEADS)
    ap.add_argument("--seeds", nargs="+", type=int, default=[0, 1, 2, 3, 4])
    ap.add_argument("--max-train", type=int, default=None,
                    help="cap train rows (high-dim memory/time)")
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args(argv)
    outdir = cfg.results_dir() / "metrics_bb" / args.dataset
    outdir.mkdir(parents=True, exist_ok=True)
    combos = [(t, s) for t in ["binary", "multiclass"] for s in
              (["stratified", "temporal"] if t == "binary" else ["stratified"])]
    ok = skip = fail = 0
    for model in args.models:
        X, ym, yb, cap = load_nfm(model, args.dataset)
        print(f"[{model}] X={X.shape}", flush=True)
        for head, (task, split), seed in itertools.product(args.heads, combos, args.seeds):
            name = f"{model}__embedding__{head}__{task}__{split}__s{seed}.json"
            if (outdir / name).exists():
                skip += 1; continue
            t0 = time.time()
            try:
                mf1 = run(model, head, task, split, seed, X, ym, yb, cap, outdir, args.max_train,
                          dataset=args.dataset)
                print(f"  [ok] {name[:-5]}: macroF1={mf1:.4f} ({time.time()-t0:.0f}s)", flush=True)
                ok += 1
            except Exception as e:  # noqa: BLE001
                print(f"  [FAIL] {name[:-5]}: {e}", flush=True); fail += 1
    print(f"B2 GRID DONE: {ok} ok, {fail} failed, {skip} skipped", flush=True)


if __name__ == "__main__":
    main()
