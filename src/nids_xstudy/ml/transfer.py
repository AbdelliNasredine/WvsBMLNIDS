"""Cross-tool transfer matrix (RQ2): train on A's R-common, test on B's R-common.

The R-common feature *schema* is identical across tools, so a model trained on
tool A can be applied to tool B directly. A performance drop on the off-diagonal
isolates *implementation semantics* — the same nominally-identical features carry
different values per tool (quantified in Phase 2). Binary task (attack/benign),
stratified split, one model.
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import f1_score

from . import dataset as D
from .models import make_pipeline


def transfer_matrix(tools, *, model="rf", seed=0, regime="common", dataset="cicids2017"):
    data, fitted = {}, {}
    for t in tools:
        df = D.load_tool(t, dataset)
        X, _ = D.feature_matrix(df, regime)
        y = D.labels(df, "binary")
        tr, te = D.split_mask(df, y, "stratified", seed)
        data[t] = (X.to_numpy("float64"), y, tr, te)

    for t in tools:  # train each tool's model on its own train split
        X, y, tr, te = data[t]
        fitted[t] = make_pipeline(model, seed).fit(X[tr], y[tr])

    rows = []
    for a in tools:
        for b in tools:
            Xb, yb, trb, teb = data[b]
            pred = fitted[a].predict(Xb[teb])
            rows.append({"train": a, "test": b,
                         "macro_f1": float(f1_score(yb[teb], pred, average="macro", zero_division=0))})
    return rows
