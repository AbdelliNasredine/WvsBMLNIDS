#!/usr/bin/env python
"""Phase B2.2: unified black-box vs white-box report.

Reads the sample-based grid in results/metrics_bb/ (5 NFMs + NFStream-common /
NFStream-native, all on the SAME 142k flows) and produces:
  * b2_master.md  -- macro-F1 per extractor x head x (task,split), mean+/-std/seeds
  * RQ-B1 : macro-F1 spread across the 5 NFMs (representation-induced variance)
  * RQ-B2 : NFMs vs NFStream hand-engineered features on identical flows
  * CD diagram over all extractors (multiclass stratified)
  * per-class recall heatmap (rare-class emphasis, HB1)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.analysis import plotting as P  # noqa: E402

P.use_style()

NFMS = ["raw-cnn", "yatc", "etbert", "netfound"]
WB = ["nfstream-common", "nfstream-native"]
ORDER = NFMS + WB
SHORT_CLASS_BY_DS = {
    "cicids2017": {"Web Attack - Brute Force": "Web Brute", "Web Attack - XSS": "Web XSS",
                   "Web Attack - Sql Injection": "Web SQLi", "DoS Slowhttptest": "DoS SlowHTTP"},
    "dapt20": {"Reconnaissance": "Recon", "Establish Foothold": "Foothold",
               "Lateral Movement": "Lateral Mv", "Data Exfiltration": "Exfil"},
}


def load(dataset):
    rows, perclass = [], []
    d = cfg.results_dir() / "metrics_bb" / dataset
    for f in d.glob("*.json"):
        r = json.loads(f.read_text(encoding="utf-8")); c, m = r["config"], r["metrics"]
        fam = "nfm" if c["tool"] in NFMS else "whitebox"
        rows.append({"tool": c["tool"], "family": fam, "head": c["model"], "task": c["task"],
                     "split": c["split"], "seed": c["seed"], "macro_f1": m["macro_f1"],
                     "balanced_acc": m["balanced_accuracy"], "fpr": m.get("fpr")})
        for cls, dd in m.get("per_class", {}).items():
            if cls not in ("accuracy", "macro avg", "weighted avg", "<unseen>"):
                perclass.append({"tool": c["tool"], "head": c["model"], "task": c["task"],
                                 "split": c["split"], "seed": c["seed"], "class": cls,
                                 "recall": dd["recall"]})
    return pd.DataFrame(rows), pd.DataFrame(perclass)


def md(df, cols, f3=("macro_f1", "std")):
    h = "| " + " | ".join(cols) + " |"; s = "| " + " | ".join("---" for _ in cols) + " |"
    body = []
    for r in df[cols].itertuples(index=False):
        cells = [f"{v:.4f}" if isinstance(v, float) else ("" if pd.isna(v) else str(v)) for v in r]
        body.append("| " + " | ".join(cells) + " |")
    return "\n".join([h, s, *body])


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args()
    ds = args.dataset
    pfx = "" if ds == "cicids2017" else f"{ds}_"
    SHORT_CLASS = SHORT_CLASS_BY_DS.get(ds, {})
    df, pc = load(ds)
    if df.empty:
        raise SystemExit("no metrics_bb yet")
    tables = cfg.results_dir() / "tables"; tables.mkdir(parents=True, exist_ok=True)
    figs = cfg.results_dir() / "figures"; figs.mkdir(parents=True, exist_ok=True)
    agg = (df.groupby(["tool", "family", "head", "task", "split"], as_index=False)
           .agg(macro_f1=("macro_f1", "mean"), std=("macro_f1", "std"),
                fpr=("fpr", "mean"), n=("seed", "nunique")))

    lines = [f"# Phase-B2 unified black-box vs white-box ({ds})", "",
             f"{len(df)} runs. Every extractor -- 5 NFM embeddings + NFStream hand-engineered",
             "features -- is evaluated on the IDENTICAL 142k flows, same heads/splits/seeds.", ""]
    for task, split in [("multiclass", "stratified"), ("binary", "temporal"), ("binary", "stratified")]:
        sub = agg[(agg.task == task) & (agg.split == split)]
        if sub.empty:
            continue
        piv = sub.pivot_table(index="tool", columns="head", values="macro_f1")
        piv = piv.reindex([t for t in ORDER if t in piv.index]).reset_index()
        lines += [f"## {task} / {split} -- macro-F1 (mean over seeds)",
                  md(piv, list(piv.columns)), ""]
        # RQ-B1 / RQ-B2 headline at each extractor's BEST head (fair: the verdict
        # flips by head -- NFM embeddings suit linear/MLP heads, hand-engineered
        # features suit trees).
        best = sub.groupby("tool")["macro_f1"].max()
        besthead = sub.loc[sub.groupby("tool")["macro_f1"].idxmax()].set_index("tool")["head"]
        nfm = best.reindex([t for t in NFMS if t in best.index])
        wb = best.reindex([t for t in WB if t in best.index])
        if len(nfm) and len(wb):
            wbn = wb.get("nfstream-native", float("nan")); wbc = wb.get("nfstream-common", float("nan"))
            verdict = "beat" if nfm.max() > max(wbn, wbc) else "lose to"
            lines += [f"*RQ-B1 (best head): NFM spread = {nfm.max()-nfm.min():.3f} "
                      f"(best {nfm.idxmax()} {nfm.max():.3f} via {besthead.get(nfm.idxmax())}, "
                      f"worst {nfm.idxmin()} {nfm.min():.3f}).*",
                      f"*RQ-B2 (best head): best NFM {nfm.max():.3f} ({nfm.idxmax()}/{besthead.get(nfm.idxmax())}) "
                      f"{verdict} NFStream-native {wbn:.3f}/common {wbc:.3f} on identical flows.*", ""]
    (tables / f"{pfx}b2_master.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # CD diagram over extractors (multiclass stratified), if enough data
    try:
        import scikit_posthocs as sp
        from scipy import stats
        sub = df[(df.task == "multiclass") & (df.split == "stratified")]
        piv = sub.pivot_table(index=["head", "seed"], columns="tool", values="macro_f1").dropna(axis=0, how="any")
        if piv.shape[0] >= 3 and piv.shape[1] >= 3:
            ranks = piv.rank(axis=1, ascending=False).mean(axis=0).sort_values()
            nem = sp.posthoc_nemenyi_friedman(piv.to_numpy()); nem.index = nem.columns = piv.columns
            fig, ax = plt.subplots(figsize=(P.COL_W, 1.9))
            sp.critical_difference_diagram(
                ranks, nem, ax=ax,
                color_palette={t: P.series_color(t, i)
                               for i, t in enumerate(ranks.index)})  # R9 colors
            ax.grid(False)
            P.savefig_both(fig, figs / f"{pfx}b2_cd_extractors"); plt.close(fig)
    except Exception as e:  # noqa: BLE001
        print(f"(CD diagram skipped: {e})")

    # per-class recall heatmap (multiclass stratified, RF, mean over seeds)
    if not pc.empty:
        p = pc[(pc.task == "multiclass") & (pc.split == "stratified") & (pc["head"] == "rf")]
        if not p.empty:
            piv = p.groupby(["tool", "class"])["recall"].mean().unstack("class")
            piv = piv.reindex([t for t in ORDER if t in piv.index])
            # 15 class columns are unreadable at 3.5 in -> the ONE sanctioned
            # R1 exception: double-column width (7.16 in).
            fig, ax = plt.subplots(figsize=(P.DBL_W, 2.4))
            P.style_heatmap(ax, 100 * piv.to_numpy(dtype="float64"),
                            row_labels=piv.index,
                            col_labels=[SHORT_CLASS.get(c, c) for c in piv.columns],
                            vmin=0, vmax=100, cbar_label="Recall [%]")
            P.savefig_both(fig, figs / f"{pfx}b2_perclass_recall"); plt.close(fig)

    print(f"wrote {tables/(pfx+'b2_master.md')}; {len(df)} runs, extractors: {sorted(df.tool.unique())}")


if __name__ == "__main__":
    main()
