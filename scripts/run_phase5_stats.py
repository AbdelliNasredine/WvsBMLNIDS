#!/usr/bin/env python
"""Phase-5: variance decomposition + significance tests + figures.

    python scripts/run_phase5_stats.py
Handles partial data (grid still running).
"""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import scikit_posthocs as sp  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.analysis import stats as S  # noqa: E402
from nids_xstudy.analysis import plotting as P  # noqa: E402

P.use_style()

TOOLS = ["nfstream", "zeek", "tranalyzer", "cicflowmeter-orig", "cicflowmeter-fixed",
         "argus", "go-flows", "yaf", "joy"]
SHORT_CLASS_BY_DS = {
    "cicids2017": {"Web Attack - Brute Force": "Web Brute", "Web Attack - XSS": "Web XSS",
                   "Web Attack - Sql Injection": "Web SQLi", "DoS Slowhttptest": "DoS SlowHTTP"},
    "dapt20": {"Reconnaissance": "Recon", "Establish Foothold": "Foothold",
               "Lateral Movement": "Lateral Mv", "Data Exfiltration": "Exfil"},
}
CELLS = [("binary", "stratified"), ("binary", "temporal"), ("multiclass", "stratified")]


def _md(df, cols):
    h = "| " + " | ".join(cols) + " |"
    s = "| " + " | ".join("---" for _ in cols) + " |"
    b = ["| " + " | ".join("" if pd.isna(v) else str(v) for v in r) + " |"
         for r in df[cols].itertuples(index=False)]
    return "\n".join([h, s, *b])


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args()
    ds = args.dataset
    pfx = "" if ds == "cicids2017" else f"{ds}_"
    SHORT_CLASS = SHORT_CLASS_BY_DS.get(ds, {})
    summ, perclass = S.load_metrics(ds)
    tables = cfg.results_dir() / "tables"; tables.mkdir(parents=True, exist_ok=True)
    figs = cfg.results_dir() / "figures"; figs.mkdir(parents=True, exist_ok=True)
    n_runs = len(summ)

    # ---- variance decomposition ----
    vrows = []
    for task, split in CELLS:
        vd = S.variance_decomposition(summ, task, split)
        if vd:
            vrows.append({"task": task, "split": split, **vd})
    vdf = pd.DataFrame(vrows)
    if not vdf.empty:
        factors = [c for c in ["tool", "model", "regime", "seed", "residual"] if c in vdf.columns]
        vlines = ["# Variance decomposition of macro-F1 (%)", "",
                  f"Type-II ANOVA within each (task, split) cell over {n_runs} runs.",
                  "The headline: how much of the performance variance is explained by",
                  "the **extractor** vs the **model**?", "",
                  _md(vdf, ["task", "split"] + factors), ""]
        (tables / f"{pfx}variance_decomposition.md").write_text("\n".join(vlines) + "\n", encoding="utf-8")
        # bar figure (one-factor design: distinct color per factor, R4).
        # Only the experimenter-controlled factors are plotted; seed and residual
        # stay in the markdown table but are omitted from the figure.
        fig_factors = [c for c in ["tool", "model", "regime"] if c in vdf.columns]
        fig, ax = plt.subplots(figsize=(P.COL_W, P.PANEL_H))
        cells = [f"{t}\n{s}" for t, s in zip(vdf.task, vdf.split)]
        series = {f: vdf[f].to_numpy(dtype="float64") for f in fig_factors}
        P.grouped_bars(ax, cells, series)
        ax.set_ylabel("Variance share [%]")
        P.top_legend(ax, ncol=len(fig_factors))
        P.savefig_both(fig, figs / f"{pfx}variance_decomposition"); plt.close(fig)

    # ---- Friedman + Nemenyi (+ CD diagrams) ----
    slines = ["# Significance tests", ""]
    for task, split in CELLS:
        fn = S.friedman_nemenyi(summ, task, split)
        if not fn:
            continue
        slines += [f"## {task} / {split}",
                   f"Friedman χ²={fn['stat']:.1f}, p={fn['p']:.2e} "
                   f"(k={fn['k_tools']} tools, {fn['n_blocks']} blocks). Lower avg rank = better.",
                   "", "avg ranks: " + ", ".join(f"**{t}** {r:.2f}" for t, r in fn["ranks"].items()), ""]
        try:
            fig, ax = plt.subplots(figsize=(P.COL_W, 1.9))
            sp.critical_difference_diagram(
                fn["ranks"], fn["nemenyi"], ax=ax,
                color_palette={t: P.series_color(t, i)
                               for i, t in enumerate(fn["ranks"].index)})  # R9 colors
            ax.grid(False)
            P.savefig_both(fig, figs / f"{pfx}cd_{task}_{split}"); plt.close(fig)
        except Exception as e:  # noqa: BLE001
            slines.append(f"(CD diagram failed: {e})")

    # ---- Wilcoxon orig vs fixed (RQ4) ----
    w = S.wilcoxon_pair(summ)
    if w:
        slines += ["## RQ4: CICFlowMeter orig vs fixed (Wilcoxon signed-rank)",
                   f"n={w['n_pairs']} paired configs; fixed wins {w['wins_fixed']}/{w['n_pairs']}; "
                   f"median Δ(fixed−orig)={w['median_delta_fixed_minus_orig']:.4f}; "
                   f"W={w['stat']:.1f}, p={w['p']:.2e}.", ""]

    # ---- H4: model-ranking stability across tools ----
    kt = S.kendall_tau_model_ranking(summ, "multiclass", "stratified", "common")
    if kt:
        slines += ["## H4: model-ranking stability across extractors (multiclass, R-common)",
                   f"Mean Kendall τ between tools' model-rankings = **{kt['mean_tau']:.3f}** "
                   f"(min {kt['min_tau']:.3f}). τ≈1 would mean identical model rankings; "
                   "lower τ means the best *model* depends on the extractor.", ""]
    (tables / f"{pfx}significance.md").write_text("\n".join(slines) + "\n", encoding="utf-8")

    # ---- tool x class F1 heatmap (multiclass stratified, R-common, mean over seeds) ----
    pc = perclass[(perclass.task == "multiclass") & (perclass.split == "stratified")
                  & (perclass.regime == "common") & (perclass.model == "rf")]
    if not pc.empty:
        piv = pc.groupby(["tool", "class"])["recall"].mean().unstack("class")
        piv = piv.reindex([t for t in TOOLS if t in piv.index])
        # 15 class columns: double-column width (the one sanctioned R1 exception;
        # supplementary figure, mirrors b2_perclass_recall).
        fig, ax = plt.subplots(figsize=(P.DBL_W, 2.6))
        P.style_heatmap(ax, 100 * piv.to_numpy(dtype="float64"),
                        row_labels=piv.index,
                        col_labels=[SHORT_CLASS.get(c, c) for c in piv.columns],
                        vmin=0, vmax=100, cbar_label="Recall [%]")
        P.savefig_both(fig, figs / f"{pfx}tool_class_recall_heatmap"); plt.close(fig)

    print(f"loaded {n_runs} runs")
    if not vdf.empty:
        print("\nVariance decomposition (% of macro-F1 variance):")
        print(vdf.to_string(index=False))
    print(f"\nwrote variance_decomposition.md, significance.md + figures")


if __name__ == "__main__":
    main()
