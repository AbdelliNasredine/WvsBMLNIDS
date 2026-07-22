#!/usr/bin/env python
"""Phase B5.3 report: label-efficiency curves + zero-shot anomaly results."""
from __future__ import annotations

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


def _md(df, cols):
    h = "| " + " | ".join(str(c) for c in cols) + " |"; s = "| " + " | ".join("---" for _ in cols) + " |"
    b = ["| " + " | ".join(f"{v:.3f}" if isinstance(v, float) else str(v) for v in r) + " |"
         for r in df[cols].itertuples(index=False)]
    return "\n".join([h, s, *b])


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args()
    ds = args.dataset
    pfx = "" if ds == "cicids2017" else f"{ds}_"
    mdir = cfg.results_dir() / "metrics_bb" / ds
    tables = cfg.results_dir() / "tables"; figs = cfg.results_dir() / "figures"
    lines = [f"# Phase-B5 label efficiency + zero-shot ({ds})", ""]

    # ---- k-shot ----
    kp = mdir / "b5_kshot.csv"
    if kp.exists():
        k = pd.read_csv(kp)
        piv = k.groupby(["extractor", "k"])["macro_f1"].mean().unstack("k")
        piv = piv.reindex([e for e in ORDER if e in piv.index])
        lines += ["## k-shot label efficiency (multiclass macro-F1, LogReg, mean/5 seeds)",
                  _md(piv.reset_index(), ["extractor"] + [c for c in piv.columns]), ""]
        # R1: k in {1,5,10,50,100} are design points -> CATEGORICAL x, never log.
        ks = list(piv.columns)
        series = {e: 100 * piv.loc[e].to_numpy(dtype="float64") for e in piv.index}
        fig, ax = plt.subplots(figsize=(P.COL_W, 2.2))
        P.line_series(ax, ks, series)
        ax.set_xlabel("Labels per class $k$")
        ax.set_ylabel("Macro-F1 [%]")
        P.top_legend(ax, ncol=3)
        P.savefig_both(fig, figs / f"{pfx}b5_label_efficiency"); plt.close(fig)
        # RQ headline: who wins at low k (k=5) and high k (k=100)
        for kk in (5, 100):
            if kk in piv.columns:
                s = piv[kk].sort_values(ascending=False)
                lines.append(f"*k={kk}: best {s.index[0]} {s.iloc[0]:.3f}; "
                             f"NFStream-native {piv.loc['nfstream-native', kk]:.3f} "
                             f"(rank {list(s.index).index('nfstream-native')+1}/{len(s)}).*")
        lines.append("")

    # ---- anomaly ----
    ap = mdir / "b5_anomaly.csv"
    if ap.exists():
        a = pd.read_csv(ap)
        best = a.loc[a.groupby("extractor")["auc_pr"].idxmax()].set_index("extractor")
        best = best.reindex([e for e in ORDER if e in best.index]).reset_index()
        lines += ["## Zero-shot anomaly detection (benign-only train; best detector per extractor)",
                  _md(best[["extractor", "detector", "auc_pr", "auc_roc"]],
                      ["extractor", "detector", "auc_pr", "auc_roc"]), ""]
        s = best.set_index("extractor")["auc_pr"].sort_values(ascending=False)
        lines.append(f"*Best zero-shot: {s.index[0]} AUC-PR {s.iloc[0]:.3f}; "
                     f"NFStream-native {best.set_index('extractor')['auc_pr'].get('nfstream-native', float('nan')):.3f}.*")

    (tables / f"{pfx}b5_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {tables/'b5_report.md'}")


if __name__ == "__main__":
    main()
