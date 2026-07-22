#!/usr/bin/env python
"""Phase-2 report + figures from the flow-alignment grid (results/phase2/categories.csv).

Produces:
  * results/tables/flow_divergence.md   — agreement matrix + per-class divergence
  * results/figures/agreement_heatmap.png — pairwise %1:1 (tool_a vs tool_b)
  * results/figures/per_class_split.png  — split/1:1 rate by traffic class (H3)

Handles partial data (only the pairs computed so far).
"""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.analysis import plotting as P  # noqa: E402

P.use_style()

SHORT_CLASS_BY_DS = {
    "cicids2017": {"Web Attack - Brute Force": "Web Brute", "Web Attack - XSS": "Web XSS",
                   "Web Attack - Sql Injection": "Web SQLi", "DoS Slowhttptest": "DoS SlowHTTP"},
    "dapt20": {"Reconnaissance": "Recon", "Establish Foothold": "Foothold",
               "Lateral Movement": "Lateral Mv", "Data Exfiltration": "Exfil"},
}
CLASS_ORDER_BY_DS = {
    "cicids2017": ["BENIGN", "PortScan", "DoS Hulk", "DDoS", "DoS GoldenEye",
                   "DoS slowloris", "DoS Slowhttptest", "FTP-Patator", "SSH-Patator",
                   "Bot", "Web Attack - Brute Force", "Web Attack - XSS",
                   "Web Attack - Sql Injection", "Infiltration", "Heartbleed"],
    "dapt20": ["BENIGN", "Reconnaissance", "Establish Foothold",
               "Lateral Movement", "Data Exfiltration"],
}

TOOLS = ["nfstream", "zeek", "tranalyzer", "cicflowmeter-orig", "cicflowmeter-fixed",
         "argus", "go-flows", "yaf", "joy"]
SHORT = {"nfstream": "nfs", "zeek": "zeek", "tranalyzer": "tran",
         "cicflowmeter-orig": "cfm-o", "cicflowmeter-fixed": "cfm-f",
         "argus": "argus", "go-flows": "goflw", "yaf": "yaf", "joy": "joy"}


def load(dataset) -> pd.DataFrame:
    p = cfg.results_dir() / "phase2" / dataset / "categories.csv"
    if not p.exists():
        raise SystemExit(f"no alignment results for {dataset} (run run_phase2_align.py --dataset {dataset})")
    return pd.read_csv(p)


def agreement_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Ordered-pair %1:1 (of tool_a's flows), summed across days, ALL class."""
    a = df[df["class"] == "ALL"].groupby(["tool_a", "tool_b"], as_index=False)[
        ["c_1to1", "n"]].sum()
    a["pct_1to1"] = a["c_1to1"] / a["n"]
    return a.pivot(index="tool_a", columns="tool_b", values="pct_1to1")


def per_class(df: pd.DataFrame, class_order) -> pd.DataFrame:
    """Aggregate category fractions per class across all ordered pairs + days."""
    g = df[df["class"] != "ALL"].groupby("class", as_index=False)[
        ["n", "c_1to1", "c_split", "c_merge", "c_unmatched"]].sum()
    for c in ["c_1to1", "c_split", "c_merge", "c_unmatched"]:
        g[c.replace("c_", "") + "_frac"] = (g[c] / g["n"]).round(4)
    order = {c: i for i, c in enumerate(class_order)}
    g["o"] = g["class"].map(lambda c: order.get(c, 99))
    return g.sort_values("o").drop(columns="o")


def heatmap(mat: pd.DataFrame, path):
    tools = [t for t in TOOLS if t in mat.index or t in mat.columns]
    M = mat.reindex(index=tools, columns=tools)
    fig, ax = plt.subplots(figsize=(P.COL_W, 2.9))
    P.style_heatmap(ax, 100 * M.to_numpy(dtype="float64"),
                    row_labels=[SHORT[t] for t in tools],
                    col_labels=[SHORT[t] for t in tools], vmin=0, vmax=100,
                    cbar_label="Flows matched 1:1 [%]", annot_size=5.5)
    ax.set_xlabel("Tool B"); ax.set_ylabel("Tool A")
    P.savefig_both(fig, path); plt.close(fig)


def per_class_fig(pc: pd.DataFrame, path, short_class):
    pc = pc[pc["n"] > 0]
    fig, ax = plt.subplots(figsize=(P.COL_W, P.PANEL_H))
    x = np.arange(len(pc))
    segs = [("1to1_frac", "1:1"), ("split_frac", "split"),
            ("merge_frac", "merge"), ("unmatched_frac", "unmatched")]
    bottom = np.zeros(len(pc))
    for i, (col, lab) in enumerate(segs):
        vals = 100 * pc[col].to_numpy(dtype="float64")
        ax.bar(x, vals, bottom=bottom, label=lab, color=P.CYCLE_COLORS[i],
               hatch=P.CYCLE_HATCHES[i], edgecolor="black", linewidth=0.8)
        bottom = bottom + vals
    ax.set_xticks(list(x))
    ax.set_xticklabels([short_class.get(c, c) for c in pc["class"]],
                       rotation=45, ha="right", rotation_mode="anchor", fontsize=6)
    ax.set_ylabel("Share of flows [%]")
    ax.set_ylim(0, 100)
    ax.grid(True, axis="y"); ax.set_axisbelow(True)
    P.top_legend(ax, ncol=4)
    P.savefig_both(fig, path); plt.close(fig)


def md_table(df, cols):
    head = "| " + " | ".join(cols) + " |"
    sep = "| " + " | ".join("---" for _ in cols) + " |"
    body = ["| " + " | ".join(("" if pd.isna(v) else (f"{v:.3f}" if isinstance(v, float) else str(v)))
                              for v in r) + " |" for r in df[cols].itertuples(index=False)]
    return "\n".join([head, sep, *body])


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args()
    ds = args.dataset
    class_order = CLASS_ORDER_BY_DS.get(ds, [])
    short_class = SHORT_CLASS_BY_DS.get(ds, {})
    pfx = "" if ds == "cicids2017" else f"{ds}_"

    df = load(ds)
    figs = cfg.results_dir() / "figures"; figs.mkdir(parents=True, exist_ok=True)
    tables = cfg.results_dir() / "tables"; tables.mkdir(parents=True, exist_ok=True)

    mat = agreement_matrix(df)
    pc = per_class(df, class_order)
    heatmap(mat, figs / f"{pfx}agreement_heatmap.png")
    per_class_fig(pc, figs / f"{pfx}per_class_split.png", short_class)

    ndone = df[["day", "tool_a", "tool_b"]].drop_duplicates().shape[0]
    days = sorted(df["day"].unique())
    lines = ["# Flow-accounting divergence (RQ3)", "",
             f"From {ndone} ordered tool-pair × day matches over days: {', '.join(days)}.",
             "Match = order-independent 5-tuple + temporal overlap; each of A's flows",
             "is 1:1, split (A coarser), merge (A finer), or unmatched vs B.", "",
             "## Pairwise agreement (% of A's flows matching 1:1 to B)",
             "row = A, col = B. See figures/agreement_heatmap.png.", "",
             md_table(mat.round(3).reset_index().rename(columns={"tool_a": "A \\ B"}),
                      ["A \\ B"] + [c for c in TOOLS if c in mat.columns]), "",
             "## Divergence by traffic class (aggregated over all tool pairs)",
             "H3: attack traffic should show far lower 1:1 (more split/merge) than benign.",
             "See figures/per_class_split.png.", "",
             md_table(pc, ["class", "n", "1to1_frac", "split_frac", "merge_frac", "unmatched_frac"]), ""]
    (tables / f"{pfx}flow_divergence.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(pc[["class", "n", "1to1_frac", "split_frac", "unmatched_frac"]].to_string(index=False))
    print(f"\nwrote {tables/(pfx+'flow_divergence.md')}, {figs/(pfx+'agreement_heatmap.png')}, {figs/(pfx+'per_class_split.png')}")


if __name__ == "__main__":
    main()
