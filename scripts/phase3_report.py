#!/usr/bin/env python
"""Aggregate Phase-3 metrics JSONs into the master results table + RQ1 figures.

    python scripts/phase3_report.py
"""
from __future__ import annotations

import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.analysis import plotting as P  # noqa: E402

P.use_style()

TOOLS = ["nfstream", "zeek", "tranalyzer", "cicflowmeter-orig", "cicflowmeter-fixed",
         "argus", "go-flows", "yaf", "joy"]
SHORT = {"nfstream": "nfs", "zeek": "zeek", "tranalyzer": "tran",
         "cicflowmeter-orig": "cfm-o", "cicflowmeter-fixed": "cfm-f",
         "argus": "argus", "go-flows": "goflw", "yaf": "yaf", "joy": "joy"}


def load(dataset) -> pd.DataFrame:
    rows = []
    for f in (cfg.results_dir() / "metrics" / dataset).glob("*.json"):
        r = json.loads(f.read_text(encoding="utf-8"))
        c, m = r["config"], r["metrics"]
        rows.append({**{k: c[k] for k in ("tool", "regime", "model", "task", "split", "seed")},
                     "n_features": c.get("n_features"), "macro_f1": m["macro_f1"],
                     "weighted_f1": m["weighted_f1"], "balanced_acc": m["balanced_accuracy"],
                     "fpr": m.get("fpr"), "auc_pr": m.get("auc_pr")})
    if not rows:
        raise SystemExit("no metrics yet (run scripts/run_phase3_ml.py)")
    return pd.DataFrame(rows)


def agg(df):
    return (df.groupby(["tool", "regime", "model", "task", "split"], as_index=False)
            .agg(macro_f1_mean=("macro_f1", "mean"), macro_f1_std=("macro_f1", "std"),
                 balanced_acc=("balanced_acc", "mean"), n_seeds=("seed", "nunique")))


def md(df, cols, fmt=None):
    fmt = fmt or {}
    head = "| " + " | ".join(cols) + " |"
    sep = "| " + " | ".join("---" for _ in cols) + " |"
    body = []
    for r in df[cols].itertuples(index=False):
        cells = []
        for col, v in zip(cols, r):
            if pd.isna(v):
                cells.append("")
            elif col in fmt:
                cells.append(fmt[col](v))
            else:
                cells.append(str(v))
        body.append("| " + " | ".join(cells) + " |")
    return "\n".join([head, sep, *body])


def rq1_figure(a, task, path):
    sub = a[(a["task"] == task) & (a["model"] == "rf") & (a["split"] == "stratified")]
    if sub.empty:
        return False
    tools = [t for t in TOOLS if t in set(sub["tool"])]
    regimes = ["common", "native"]
    fig, ax = plt.subplots(figsize=(P.COL_W, P.PANEL_H))
    # Two-factor design with factor 'tool' on the x-axis -> single-color bars,
    # hatch differentiates the regime (R4 single-color variant).
    series, yerr = {}, {}
    for rg in regimes:
        series[f"R-{rg}"] = [100 * sub[(sub.tool == t) & (sub.regime == rg)]["macro_f1_mean"].mean()
                             for t in tools]
        yerr[f"R-{rg}"] = [100 * sub[(sub.tool == t) & (sub.regime == rg)]["macro_f1_std"].mean()
                           for t in tools]
    P.grouped_bars(ax, [SHORT[t] for t in tools], series, yerr=yerr,
                   colors=["#2ca02c", "#2ca02c"], hatches=[None, "//"], rotate=45)
    ax.set_ylabel("Macro-F1 [%]")
    ax.set_xlabel("Extractor")
    P.top_legend(ax, ncol=2)
    P.savefig_both(fig, path); plt.close(fig)
    return True


def rq4_delta(tables, dataset, pfx=""):
    """CICFlowMeter orig-vs-fixed ML performance delta (the RQ4 'bug impact')."""
    mdir = cfg.results_dir() / "metrics" / dataset
    recs = {}
    for tool in ("cicflowmeter-orig", "cicflowmeter-fixed"):
        for f in mdir.glob(f"{tool}__*.json"):
            r = json.loads(f.read_text(encoding="utf-8"))
            c = r["config"]
            recs[(tool, c["regime"], c["model"], c["task"])] = r
    lines = ["# RQ4 — CICFlowMeter orig vs fixed: ML impact of the 'bug'", "",
             "Same everything except the extractor code (the DistriNet fix removes",
             "the TCP-appendix flows and corrects counting). Macro-F1 delta:", ""]
    rows = []
    for (tool, rg, mdl, tsk), r in recs.items():
        if tool != "cicflowmeter-orig":
            continue
        fx = recs.get(("cicflowmeter-fixed", rg, mdl, tsk))
        if not fx:
            continue
        o, f = r["metrics"]["macro_f1"], fx["metrics"]["macro_f1"]
        rows.append({"regime": rg, "model": mdl, "task": tsk,
                     "orig_macroF1": round(o, 4), "fixed_macroF1": round(f, 4),
                     "delta(fixed-orig)": round(f - o, 4)})
    if rows:
        d = pd.DataFrame(rows).sort_values(["task", "regime", "model"])
        head = "| " + " | ".join(d.columns) + " |"
        sep = "| " + " | ".join("---" for _ in d.columns) + " |"
        body = ["| " + " | ".join(str(v) for v in r) + " |" for r in d.itertuples(index=False)]
        lines += ["\n".join([head, sep, *body]), ""]
        # per-class recall delta on multiclass R-common RF
        o = recs.get(("cicflowmeter-orig", "common", "rf", "multiclass"))
        f = recs.get(("cicflowmeter-fixed", "common", "rf", "multiclass"))
        if o and f:
            lines += ["", "## Per-class recall delta (R-common RF multiclass)", ""]
            pco, pcf = o["metrics"]["per_class"], f["metrics"]["per_class"]
            pr = [{"class": k, "orig_recall": round(pco[k]["recall"], 3),
                   "fixed_recall": round(pcf.get(k, {}).get("recall", float("nan")), 3)}
                  for k in pco if k not in ("accuracy", "macro avg", "weighted avg", "<unseen>")]
            pdf = pd.DataFrame(pr)
            pdf["delta"] = (pdf["fixed_recall"] - pdf["orig_recall"]).round(3)
            head = "| " + " | ".join(pdf.columns) + " |"
            sep = "| " + " | ".join("---" for _ in pdf.columns) + " |"
            body = ["| " + " | ".join(str(v) for v in r) + " |" for r in pdf.itertuples(index=False)]
            lines += ["\n".join([head, sep, *body]), ""]
    (tables / f"{pfx}rq4_bug_impact.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args()
    ds = args.dataset
    pfx = "" if ds == "cicids2017" else f"{ds}_"
    df = load(ds)
    a = agg(df)
    tables = cfg.results_dir() / "tables"; tables.mkdir(parents=True, exist_ok=True)
    figs = cfg.results_dir() / "figures"; figs.mkdir(parents=True, exist_ok=True)

    f3 = lambda v: f"{v:.4f}"
    lines = ["# Phase-3 ML results (RQ1) — master table", "",
             f"{len(df)} runs; macro-F1 mean±std over seeds. Extractor is the only",
             "independent variable within each (regime, model, task, split).", ""]
    for task in ["binary", "multiclass"]:
        for regime in ["common", "native"]:
            sub = a[(a.task == task) & (a.regime == regime) & (a.split == "stratified")]
            if sub.empty:
                continue
            piv = sub.pivot_table(index="tool", columns="model", values="macro_f1_mean")
            piv = piv.reindex([t for t in TOOLS if t in piv.index]).reset_index()
            spread = piv.drop(columns="tool").max().max() - piv.drop(columns="tool").min().min()
            lines += [f"## {task} — R-{regime} (stratified) — macro-F1",
                      f"tool-induced spread (max−min across tools/models): **{spread:.4f}**", "",
                      md(piv, list(piv.columns),
                         {c: f3 for c in piv.columns if c != "tool"}), ""]
    (tables / f"{pfx}ml_master.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rq4_delta(tables, ds, pfx)

    made = []
    for task in ["binary", "multiclass"]:
        if rq1_figure(a, task, figs / f"{pfx}rq1_{task}_macrof1.png"):
            made.append(f"{pfx}rq1_{task}_macrof1.png")

    # console summary: multiclass R-common RF spread (the headline)
    sub = a[(a.task == "multiclass") & (a.regime == "common") & (a.model == "rf")]
    if not sub.empty:
        s = sub.set_index("tool")["macro_f1_mean"].reindex([t for t in TOOLS if t in set(sub.tool)])
        print("Multiclass R-common RandomForest macro-F1 by tool:")
        print(s.round(4).to_string())
        print(f"  spread (max-min): {s.max()-s.min():.4f}")
    print(f"\nwrote {tables/(pfx+'ml_master.md')} + figures {made}")


if __name__ == "__main__":
    main()
