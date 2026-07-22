#!/usr/bin/env python
"""Phase-2c: feature-value divergence on 1:1 matched flows.

For a reference set of tool pairs, match flows, and on the clean 1:1 subset
compare *nominally identical* features (duration, total packets, total bytes)
between the two tools: paired relative error + a KS statistic between the two
tools' value distributions. Direction-agnostic aggregates are used so tools that
orient a flow differently are still comparable.

    python scripts/run_phase2_features.py
"""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from scipy import stats  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.flow_alignment.align import match_pair  # noqa: E402

# reference pairs: within-cluster, cross-cluster, and the RQ4 orig-vs-fixed pair
REF_PAIRS = [
    ("cicflowmeter-orig", "cicflowmeter-fixed"),  # RQ4: same code lineage
    ("nfstream", "zeek"),
    ("zeek", "tranalyzer"),
    ("nfstream", "yaf"),
]
FEATS = ["duration", "tot_pkts", "tot_bytes"]
COLS = ["src_ip", "src_port", "dst_ip", "dst_port", "proto", "t_start", "t_end",
        "duration", "pkts_fwd", "pkts_bwd", "bytes_fwd", "bytes_bwd", "label"]


def _load(tool, dataset):
    frames = []
    for cap in cfg.captures(dataset):
        p = cfg.labeled_dir(dataset, tool) / f"{cap}.parquet"
        if p.exists():
            frames.append(pd.read_parquet(p, columns=COLS))
    df = pd.concat(frames, ignore_index=True)
    df["tot_pkts"] = df["pkts_fwd"].fillna(0) + df["pkts_bwd"].fillna(0)
    df["tot_bytes"] = df["bytes_fwd"].fillna(0) + df["bytes_bwd"].fillna(0)
    return df


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args()
    ds = args.dataset
    pfx = "" if ds == "cicids2017" else f"{ds}_"
    rows, viol = [], {f: {} for f in FEATS}
    for a, b in REF_PAIRS:
        A, B = _load(a, ds), _load(b, ds)
        _, pairs = match_pair(A, B)
        if not len(pairs):
            continue
        av = A.iloc[pairs["ia"].to_numpy()].reset_index(drop=True)
        bv = B.iloc[pairs["ib"].to_numpy()].reset_index(drop=True)
        for f in FEATS:
            x = av[f].to_numpy(dtype="float64")
            y = bv[f].to_numpy(dtype="float64")
            m = np.isfinite(x) & np.isfinite(y)
            x, y = x[m], y[m]
            rel = (y - x) / (np.abs(x) + 1.0)
            ks = stats.ks_2samp(x, y).statistic if len(x) > 1 else np.nan
            rows.append({
                "pair": f"{a} vs {b}", "feature": f, "n_1to1": int(len(x)),
                "median_rel_err": round(float(np.median(rel)), 4),
                "mean_abs_rel_err": round(float(np.mean(np.abs(rel))), 4),
                "frac_within_5pct": round(float(np.mean(np.abs(rel) < 0.05)), 4),
                "ks_stat": round(float(ks), 4),
            })
            # sample for violins (cap for plotting)
            idx = np.random.default_rng(0).choice(len(rel), size=min(len(rel), 20000), replace=False) if len(rel) else []
            viol[f][f"{a}\nvs\n{b}"] = np.clip(rel[idx], -1, 2)
        print(f"[ok] {a} vs {b}: {len(pairs):,} 1:1 flows", flush=True)

    res = pd.DataFrame(rows)
    tables = cfg.results_dir() / "tables"; tables.mkdir(parents=True, exist_ok=True)
    figs = cfg.results_dir() / "figures"; figs.mkdir(parents=True, exist_ok=True)

    def md(df, cols):
        h = "| " + " | ".join(cols) + " |"
        s = "| " + " | ".join("---" for _ in cols) + " |"
        b = ["| " + " | ".join(str(v) for v in r) + " |" for r in df[cols].itertuples(index=False)]
        return "\n".join([h, s, *b])

    lines = ["# Feature-value divergence on 1:1 matched flows (RQ2/RQ3)", "",
             "For flows that BOTH tools segment identically (1:1), how much do the",
             "*values* of nominally-identical features differ? relative error =",
             "(B-A)/(|A|+1); KS = 2-sample KS statistic between the tools' value",
             "distributions on the matched flows. Byte counts differ by construction",
             "(IP vs payload vs L7 semantics); duration/packets should be close.", "",
             md(res, ["pair", "feature", "n_1to1", "median_rel_err",
                      "mean_abs_rel_err", "frac_within_5pct", "ks_stat"]), ""]
    (tables / f"{pfx}feature_divergence.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # violin figure per feature
    fig, axes = plt.subplots(1, len(FEATS), figsize=(5 * len(FEATS), 5))
    for ax, f in zip(axes, FEATS):
        labels = list(viol[f].keys())
        data = [viol[f][k] for k in labels]
        if data:
            ax.violinplot(data, showmedians=True)
            ax.set_xticks(range(1, len(labels) + 1)); ax.set_xticklabels(labels, fontsize=7)
        ax.axhline(0, color="k", lw=0.6, ls="--")
        ax.set_title(f); ax.set_ylabel("relative error (B-A)/(|A|+1)")
    fig.suptitle("Feature-value relative error on 1:1 matched flows")
    fig.tight_layout(); fig.savefig(figs / f"{pfx}feature_relerr_violins.png", dpi=140); plt.close(fig)

    print(res.to_string(index=False))
    print(f"\nwrote {tables/(pfx+'feature_divergence.md')}, {figs/(pfx+'feature_relerr_violins.png')}")


if __name__ == "__main__":
    main()
