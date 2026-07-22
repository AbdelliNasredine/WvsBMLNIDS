"""Train one model on one tool's flows and emit a provenance-stamped metrics JSON."""
from __future__ import annotations

import json
import time

import numpy as np
from sklearn.metrics import (average_precision_score, balanced_accuracy_score,
                             classification_report, confusion_matrix, f1_score)

from .. import config as cfg
from ..extraction.base import config_hash, git_commit
from . import dataset as D
from .models import make_pipeline


def _cap_train(tr, y_raw, max_train, seed):
    """Stratified subsample of the TRAIN mask to <= max_train rows (rare classes kept)."""
    from sklearn.model_selection import train_test_split as tts
    tr_idx = np.where(tr)[0]
    if max_train is None or len(tr_idx) <= max_train:
        return tr
    yy = y_raw[tr_idx]
    vals, counts = np.unique(yy, return_counts=True)
    rare = set(vals[counts < 2].tolist())
    rare_idx = tr_idx[np.isin(yy, list(rare))] if rare else np.array([], dtype=int)
    rest = tr_idx[~np.isin(yy, list(rare))]
    n_keep = max(1, max_train - len(rare_idx))
    if n_keep >= len(rest):
        keep = tr_idx
    else:
        keep, _ = tts(rest, train_size=n_keep, random_state=seed, stratify=y_raw[rest])
        keep = np.concatenate([keep, rare_idx])
    out = np.zeros(len(tr), bool); out[keep] = True
    return out


def run(tool, regime, model_name, task, split_kind, seed, *, dataset="cicids2017",
        include_port=False, subsample_benign=None, save=True, df=None,
        max_train=None, metrics_dir=None, tag="") -> dict:
    t0 = time.time()
    if df is None:
        df = D.load_tool(tool, dataset)
    y_raw = D.labels(df, task)
    tr, te = D.split_mask(df, y_raw, split_kind, seed, dataset=dataset)

    # optional benign subsampling on the TRAIN split only (documented ratio)
    if subsample_benign and task == "binary":
        rng = np.random.default_rng(seed)
        benign_tr = np.where(tr & (y_raw == 0))[0]
        if len(benign_tr) > subsample_benign:
            drop = rng.choice(benign_tr, len(benign_tr) - subsample_benign, replace=False)
            tr = tr.copy(); tr[drop] = False

    tr = _cap_train(tr, y_raw, max_train, seed)

    X, feats = D.feature_matrix(df, regime, include_port=include_port)
    Xtr, Xte = X.to_numpy()[tr], X.to_numpy()[te]

    # label encoding from train classes
    classes = sorted(set(y_raw[tr].tolist()))
    idx = {c: i for i, c in enumerate(classes)}
    phantom = len(classes)
    ytr = np.array([idx[c] for c in y_raw[tr]], dtype=int)
    yte = np.array([idx.get(c, phantom) for c in y_raw[te]], dtype=int)
    class_names = [str(c) for c in classes] + (["<unseen>"] if (yte == phantom).any() else [])

    pipe = make_pipeline(model_name, seed)
    pipe.fit(Xtr, ytr)
    pred = pipe.predict(Xte)

    rep = classification_report(yte, pred, labels=list(range(len(class_names))),
                                target_names=class_names, output_dict=True, zero_division=0)
    metrics = {
        "macro_f1": float(f1_score(yte, pred, average="macro", labels=list(range(len(classes))), zero_division=0)),
        "weighted_f1": float(f1_score(yte, pred, average="weighted", zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(yte, pred)),
        "per_class": {cn: {k: float(rep[cn][k]) for k in ("precision", "recall", "f1-score", "support")}
                      for cn in class_names if cn in rep},
    }
    if task == "binary":
        cm = confusion_matrix(yte, pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        metrics["fpr"] = float(fp / (fp + tn)) if (fp + tn) else 0.0
        metrics["attack_recall"] = float(tp / (tp + fn)) if (tp + fn) else 0.0
        metrics["attack_precision"] = float(tp / (tp + fp)) if (tp + fp) else 0.0
        try:
            proba = pipe.predict_proba(Xte)[:, 1]
            metrics["auc_pr"] = float(average_precision_score((yte == 1).astype(int), proba))
        except Exception:
            metrics["auc_pr"] = None
    metrics["confusion_matrix"] = confusion_matrix(yte, pred).tolist()
    metrics["class_order"] = class_names

    fi = None
    clf = pipe.named_steps["clf"]
    if hasattr(clf, "feature_importances_"):
        fi = dict(sorted(zip(feats, [float(x) for x in clf.feature_importances_]),
                         key=lambda kv: -kv[1])[:20])

    config = {"tool": tool, "regime": regime, "model": model_name, "task": task,
              "split": split_kind, "seed": seed, "include_port": include_port,
              "dataset": dataset, "n_features": len(feats), "subsample_benign": subsample_benign,
              "max_train": max_train}
    rec = {"config": config, "config_hash": config_hash(config),
           "git_commit": git_commit(), "n_train": int(tr.sum()), "n_test": int(te.sum()),
           "n_test_unseen_class": int((yte == phantom).sum()),
           "features": feats, "metrics": metrics, "feature_importances": fi,
           "wall_seconds": round(time.time() - t0, 1)}

    if save:
        out = metrics_dir or (cfg.results_dir() / "metrics")
        out.mkdir(parents=True, exist_ok=True)
        suffix = f"__{tag}" if tag else ""
        name = f"{tool}__{regime}__{model_name}__{task}__{split_kind}__s{seed}{suffix}.json"
        (out / name).write_text(json.dumps(rec, indent=2), encoding="utf-8")
    return rec
