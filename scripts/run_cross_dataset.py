#!/usr/bin/env python
"""RQ5 / H5: cross-dataset generalization under every extractor (CICIDS2017 <-> DAPT20).

Does a NIDS trained on one dataset's flows generalize to another, and does the
generalization gap depend on the *extractor*? Binary task only (ATTACK/BENIGN is
the sole shared label space; the multiclass taxonomies differ). Two families,
one protocol:

  * white-box: per tool, R-common features (the 9-ish harmonized core columns
    that mean the same thing on both datasets).
  * black-box: per NFM, the frozen sample embeddings (same model => same dim on
    both datasets), plus NFStream-common as the hand-engineered reference.

For each (extractor, source dataset): fit preprocessing + classifier on the
source's stratified 70% train, then score macro-F1 on (a) the source's 30% test
(in-distribution) and (b) ALL of the target dataset (cross-dataset). The
in-distribution minus cross gap is the generalization collapse.

    python scripts/run_cross_dataset.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent / "blackbox"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import f1_score  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.analysis import plotting as P  # noqa: E402
from nids_xstudy.ml import dataset as D  # noqa: E402
from nids_xstudy.ml.models import make_pipeline  # noqa: E402

P.use_style()

DATASETS = ["cicids2017", "dapt20"]
WB_TOOLS = ["nfstream", "zeek", "tranalyzer", "cicflowmeter-orig", "cicflowmeter-fixed",
            "argus", "go-flows", "yaf", "joy"]
NFMS = ["raw-cnn", "yatc", "etbert", "netfound"]
SEEDS = [0, 1, 2, 3, 4]
HEAD = "rf"          # tree head: fair to hand-engineered + robust across feature scales
MAX_TRAIN = 120000   # cap for speed; binary is easy so this saturates


def wb_matrix(tool, dataset):
    """(X R-common float64, y binary int) for a white-box tool on a dataset."""
    df = D.load_tool(tool, dataset)
    X, _ = D.feature_matrix(df, "common")
    y = D.labels(df, "binary")
    return X.to_numpy("float64"), y


def bb_matrix(model, dataset):
    """(X sample embeddings, y binary int) for an NFM (or nfstream-common)."""
    from run_b2_grid import load_nfm
    X, _ym, yb, _caps = load_nfm(model, dataset)
    return X.astype("float64"), yb


def evaluate(extractor, loader):
    """Fit on each source's 70% train; score source-test (in-dist) + all-target (cross).
    Returns rows: {extractor, source, target, kind, macro_f1(mean/std over seeds)}."""
    data = {}
    for ds in DATASETS:
        try:
            X, y = loader(extractor, ds)
        except Exception as e:  # noqa: BLE001
            print(f"  [skip] {extractor} {ds}: {e}", flush=True)
            return []
        data[ds] = (X, y)

    rows = []
    for src in DATASETS:
        Xs, ys = data[src]
        for tgt in DATASETS:
            Xt, yt = data[tgt]
            f1s = []
            for seed in SEEDS:
                # source split (stratified 70/30, rare-safe)
                dfcap = pd.DataFrame({"_capture": np.zeros(len(ys))})  # single block
                tr, te = D.split_mask(dfcap, ys, "stratified", seed)
                idx_tr = np.where(tr)[0]
                if len(idx_tr) > MAX_TRAIN:
                    rng = np.random.default_rng(seed)
                    idx_tr = rng.choice(idx_tr, MAX_TRAIN, replace=False)
                pipe = make_pipeline(HEAD, seed).fit(Xs[idx_tr], ys[idx_tr])
                if tgt == src:
                    pred = pipe.predict(Xs[te]); truth = ys[te]        # in-distribution
                else:
                    pred = pipe.predict(Xt); truth = yt                # cross-dataset
                f1s.append(f1_score(truth, pred, average="macro", zero_division=0))
            rows.append({"extractor": extractor, "source": src, "target": tgt,
                         "kind": "in-dist" if src == tgt else "cross",
                         "macro_f1": float(np.mean(f1s)), "std": float(np.std(f1s))})
    return rows


def main():
    all_rows = []
    print("== white-box (R-common) ==", flush=True)
    for tool in WB_TOOLS:
        r = evaluate(tool, wb_matrix)
        all_rows += [{**x, "family": "white-box"} for x in r]
        if r:
            print(f"  [ok] {tool}", flush=True)
    print("== black-box (embeddings) ==", flush=True)
    for m in NFMS + ["nfstream-common"]:
        fam = "nfm" if m in NFMS else "hand-engineered"
        r = evaluate(m, bb_matrix)
        all_rows += [{**x, "family": fam} for x in r]
        if r:
            print(f"  [ok] {m}", flush=True)

    df = pd.DataFrame(all_rows)
    tables = cfg.results_dir() / "tables"; tables.mkdir(parents=True, exist_ok=True)
    figs = cfg.results_dir() / "figures"; figs.mkdir(parents=True, exist_ok=True)

    # collapse per (extractor, source->target direction)
    piv = df.pivot_table(index=["family", "extractor"], columns=["source", "target"],
                         values="macro_f1")
    lines = ["# RQ5 cross-dataset generalization (binary macro-F1, RF head)", "",
             "Train on the SOURCE dataset's 70% (R-common features for white-box tools;",
             "frozen sample embeddings for NFMs), evaluate in-distribution (source test)",
             "and cross-dataset (all of the target). Mean over 5 seeds.", "",
             "For each direction, the in-dist minus cross gap is the generalization",
             "collapse; H5 asks whether that collapse depends on the extractor.", ""]
    # build a readable table: extractor | CIC in | CIC->DAPT | DAPT in | DAPT->CIC | mean collapse
    def g(ex, s, t):
        m = df[(df.extractor == ex) & (df.source == s) & (df.target == t)]
        return float(m["macro_f1"].iloc[0]) if len(m) else float("nan")
    hdr = "| family | extractor | CIC in-dist | CIC→DAPT | DAPT in-dist | DAPT→CIC | mean collapse |"
    sep = "| " + " | ".join("---" for _ in range(7)) + " |"
    body = []
    for (fam, ex), _ in piv.iterrows():
        ci, cx = g(ex, "cicids2017", "cicids2017"), g(ex, "cicids2017", "dapt20")
        di, dx = g(ex, "dapt20", "dapt20"), g(ex, "dapt20", "cicids2017")
        collapse = np.nanmean([ci - cx, di - dx])
        body.append(f"| {fam} | {ex} | {ci:.3f} | {cx:.3f} | {di:.3f} | {dx:.3f} | {collapse:.3f} |")
    lines += ["\n".join([hdr, sep, *body]), ""]
    (tables / "cross_dataset.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # figure: grouped bars of in-dist vs cross, per extractor (both directions averaged)
    order = [ex for _, ex in piv.index]
    indist = [np.nanmean([g(e, "cicids2017", "cicids2017"), g(e, "dapt20", "dapt20")]) for e in order]
    cross = [np.nanmean([g(e, "cicids2017", "dapt20"), g(e, "dapt20", "cicids2017")]) for e in order]
    fig, ax = plt.subplots(figsize=(P.DBL_W, 2.6))
    P.grouped_bars(ax, order, {"in-distribution": 100 * np.array(indist),
                               "cross-dataset": 100 * np.array(cross)})
    ax.set_ylabel("Macro-F1 [%]")
    ax.set_xticklabels(order, rotation=45, ha="right", rotation_mode="anchor", fontsize=6)
    P.top_legend(ax, ncol=2)
    P.savefig_both(fig, figs / "cross_dataset"); plt.close(fig)

    print(f"\nwrote {tables/'cross_dataset.md'}, {figs/'cross_dataset.png'}")
    print(df.groupby(["family", "kind"])["macro_f1"].mean().round(3).to_string())


if __name__ == "__main__":
    main()
