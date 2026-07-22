#!/usr/bin/env python
"""Phase-4 ablation report: timeout sensitivity, directionality, dst_port,
label-noise. Reads whatever ablation outputs exist. -> results/tables/ablations.md
+ figures. """
from __future__ import annotations

import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from nids_xstudy import canonical as C  # noqa: E402
from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.analysis import plotting as P  # noqa: E402
from nids_xstudy.labeling import label_dataset  # noqa: E402

P.use_style()

# per-dataset (focus capture, focus attack class) for the timeout figure.
FOCUS_BY_DS = {
    "cicids2017": ("Wednesday", "DoS Hulk"),
    "dapt20": ("thursday-pvt", "Lateral Movement"),  # the 89M-packet SSH-flood capture
}


def _mdtable(df, cols):
    h = "| " + " | ".join(str(c) for c in cols) + " |"
    s = "| " + " | ".join("---" for _ in cols) + " |"
    b = ["| " + " | ".join("" if pd.isna(v) else str(v) for v in r) + " |"
         for r in df[cols].itertuples(index=False)]
    return "\n".join([h, s, *b])


def timeout_section(figs, ds, pfx):
    ABL = cfg.data_root() / "ablation" / "timeout" / ds
    if not ABL.exists():
        return None, None
    focus_day, focus_cls = FOCUS_BY_DS.get(ds, (None, None))
    rows = []
    for td in sorted(ABL.glob("*_t*")):
        tool, T = td.name.rsplit("_t", 1)
        for pq in td.glob("*.parquet"):
            lab = label_dataset(C.read(pq), ds, cfg, capture=pq.stem)
            vc = lab["label"].value_counts()
            rows.append({"tool": tool, "timeout": int(T), "day": pq.stem,
                         "total": len(lab), "focus_class": int(vc.get(focus_cls, 0))})
    if not rows:
        return None, None
    df = pd.DataFrame(rows).sort_values(["tool", "day", "timeout"])
    # figure: TOTAL flow count vs idle timeout on the focus capture, per tool.
    # R1: uneven design points {15,60,120,600} are CATEGORICAL on x (never log-x);
    # counts span decades, so log-y is the sanctioned R6-style choice. Total flows
    # (dataset-agnostic) directly shows how the timeout policy merges/splits flows;
    # for DAPT thursday-pvt the 89M-packet SSH flood makes this dramatic.
    sub = df[df.day == focus_day]
    if not sub.empty:
        timeouts = sorted(sub["timeout"].unique())
        series = {tool: g.set_index("timeout")["total"].reindex(timeouts).to_numpy()
                  for tool, g in sub.groupby("tool")}
        fig, ax = plt.subplots(figsize=(P.COL_W, P.PANEL_H))
        P.line_series(ax, timeouts, series)
        ax.set_yscale("log")
        ax.set_xlabel("Idle timeout [s]")
        ax.set_ylabel("Total flows [count]")
        ax.grid(True, axis="y", which="both")
        P.top_legend(ax)
        P.savefig_both(fig, figs / f"{pfx}timeout_sensitivity"); plt.close(fig)
    piv = df.pivot_table(index=["tool", "day"], columns="timeout", values="total").reset_index()
    return df, piv


def directionality_section(ds):
    """Unidirectional treatment: each bidirectional flow -> a forward uni-flow
    plus (if it has reverse packets) a backward uni-flow. Shows how uni-mode
    changes flow counts and surfaces asymmetric (one-directional) traffic.

    NB: Argus is biflow-native in our config (a racluster-level 'uni' produced
    identical output), so we derive the uni-equivalent from the bidirectional
    canonical records, which generalizes across the bidirectional tools.
    """
    rows = []
    for tool in ["argus", "nfstream", "zeek", "yaf", "tranalyzer"]:
        bi_tot = uni_tot = asym = 0
        n_caps = 0
        for cap in cfg.captures(ds):
            p = cfg.canonical_dir(ds, tool) / f"{cap}.parquet"
            if not p.exists():
                continue
            df = C.read(p)
            has_bwd = int((df["pkts_bwd"].fillna(0) > 0).sum())
            bi_tot += len(df); uni_tot += len(df) + has_bwd
            asym += len(df) - has_bwd; n_caps += 1
        if n_caps:
            rows.append({"tool": tool, "bi_flows": bi_tot, "uni_equiv_flows": uni_tot,
                         "uni/bi": round(uni_tot / bi_tot, 3),
                         "%asymmetric_no_bwd": round(asym / bi_tot, 3)})
    return pd.DataFrame(rows) if rows else None


def _load_metrics(d, suffix=""):
    out = {}
    for f in d.glob("*.json"):
        r = json.loads(f.read_text(encoding="utf-8"))
        c = r["config"]
        key = (c["tool"], c["model"], c["task"], c["split"], c["seed"])
        out[key] = r["metrics"]["macro_f1"]
    return out


def ml_ablation_section(ds):
    # restrict baseline to common regime configs matching the ablation slice
    base_common = {}
    for f in (cfg.results_dir() / "metrics" / ds).glob("*__common__*.json"):
        r = json.loads(f.read_text(encoding="utf-8")); c = r["config"]
        base_common[(c["tool"], c["model"], c["task"], c["split"], c["seed"])] = r["metrics"]["macro_f1"]
    rows = []
    for name, sub in [("dst_port", "port"), ("label_noise(exact)", "exact")]:
        d = cfg.results_dir() / "ablations" / ds / sub
        if not d.exists():
            continue
        for f in d.glob("*.json"):
            r = json.loads(f.read_text(encoding="utf-8")); c = r["config"]
            key = (c["tool"], c["model"], c["task"], c["split"], c["seed"])
            if key in base_common:
                rows.append({"ablation": name, "task": c["task"], "split": c["split"],
                             "delta": r["metrics"]["macro_f1"] - base_common[key]})
    if not rows:
        return None
    d = pd.DataFrame(rows)
    g = (d.groupby(["ablation", "task", "split"])["delta"]
         .agg(n="count", mean_delta="mean", median_delta="median").reset_index())
    g["mean_delta"] = g["mean_delta"].round(4); g["median_delta"] = g["median_delta"].round(4)
    return g


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args()
    ds = args.dataset
    pfx = "" if ds == "cicids2017" else f"{ds}_"
    focus_day, focus_cls = FOCUS_BY_DS.get(ds, ("?", "?"))
    figs = cfg.results_dir() / "figures"; figs.mkdir(parents=True, exist_ok=True)
    tables = cfg.results_dir() / "tables"; tables.mkdir(parents=True, exist_ok=True)
    lines = [f"# Phase-4 ablations ({ds})", ""]

    tdf, tpiv = timeout_section(figs, ds, pfx)
    if tpiv is not None:
        lines += [f"## Timeout ablation — total flow count vs idle timeout",
                  f"See figures/{pfx}timeout_sensitivity.png ({focus_day}, focus class "
                  f"{focus_cls}). Fewer flows at longer timeout = more merging. Whether",
                  "tools converge at equal timeout tells us if the timeout *policy* (vs",
                  "tool identity) drove the divergence.", "",
                  _mdtable(tpiv, list(tpiv.columns)), ""]

    ddf = directionality_section(ds)
    if ddf is not None:
        lines += ["## Directionality ablation — unidirectional vs bidirectional", "",
                  _mdtable(ddf, list(ddf.columns)), ""]

    ml = ml_ablation_section(ds)
    if ml is not None:
        lines += ["## ML ablations (macro-F1 Δ vs R-common baseline, by setting)",
                  "dst_port is a **shortcut**: it helps in-distribution (stratified) but",
                  "hurts cross-time generalization (temporal). Label-noise (dropping",
                  "window-edge flows) has a negligible effect (robust labeling).", "",
                  _mdtable(ml, ["ablation", "task", "split", "n", "mean_delta", "median_delta"]), ""]

    (tables / f"{pfx}ablations.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if tpiv is not None:
        print("Timeout (DoS Hulk flows):"); print(tpiv.to_string(index=False))
    if ddf is not None:
        print("\nDirectionality:"); print(ddf.to_string(index=False))
    if ml is not None:
        print("\nML ablations:"); print(ml.to_string(index=False))
    print(f"\nwrote {tables/(pfx+'ablations.md')}")


if __name__ == "__main__":
    main()
