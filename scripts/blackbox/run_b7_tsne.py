#!/usr/bin/env python
"""t-SNE visualization of the black-box embedding spaces (qualitative RQ-B1/B2).

Projects the SAME sampled flows through every neural extractor's representation
with t-SNE and draws per-class seaborn KDE density contours (unfilled coloured
contours per class, benign green, no axis ticks). Because the sample rows are
aligned across extractors, every panel shows the identical flows, so differences
between panels are due to the representation alone.

Outputs one panel per extractor (tsne_<name>.png/.pdf) plus a per-dataset legend
strip (tsne_legend.png/.pdf). Run once per dataset; the paper composes the two
datasets as a two-row grid in LaTeX via subfig.

    python scripts/blackbox/run_b7_tsne.py --dataset cicids2017   # nids-xstudy, CPU
    python scripts/blackbox/run_b7_tsne.py --dataset dapt20
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import seaborn as sns  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from sklearn.decomposition import PCA  # noqa: E402
from sklearn.impute import SimpleImputer  # noqa: E402
from sklearn.manifold import TSNE  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.analysis import plotting as P  # noqa: E402
from run_b2_grid import load_nfm  # noqa: E402

P.use_style()

# the four neural foundation models (the hand-engineered NFStream reference is
# not shown here -- it is compared quantitatively elsewhere).
EXTRACTORS = ["raw-cnn", "yatc", "etbert", "netfound"]
# 5 classes with distinct characters; benign green per R6, attacks distinct.
CLASSES_BY_DS = {
    "cicids2017": {"BENIGN": "#2ca02c", "DoS Hulk": "#d62728", "PortScan": "#9467bd",
                   "FTP-Patator": "#ff7f0e", "Web Attack - Brute Force": "#1f77b4"},
    "dapt20": {"BENIGN": "#2ca02c", "Reconnaissance": "#d62728", "Establish Foothold": "#9467bd",
               "Lateral Movement": "#ff7f0e", "Data Exfiltration": "#1f77b4"},
}
N_PER_CLASS = 800
SEED = 0


def pick_rows(dataset, CLASSES):
    """Shared row indices (into the concatenated sample) per class."""
    sdir = cfg.assembled_dir(dataset, "sample")
    labs = np.concatenate([
        pd.read_parquet(sdir / f"{c}.meta.parquet")["label"].astype("string")
        .fillna("BENIGN").to_numpy() for c in cfg.captures(dataset)])
    rng = np.random.default_rng(SEED)
    idx = []
    for cls in CLASSES:
        rows = np.where(labs == cls)[0]
        if len(rows) > N_PER_CLASS:
            rows = rng.choice(rows, N_PER_CLASS, replace=False)
        idx.append(rows)
    return np.concatenate(idx), labs


def kde_contours(ax, pts, color):
    """Unfilled seaborn KDE contours for one class's 2-D points. Collapsed or
    tiny clusters fall back to a light scatter."""
    if len(pts) < 20:
        ax.scatter(pts[:, 0], pts[:, 1], s=4, color=color, alpha=0.6, linewidths=0)
        return
    try:
        sns.kdeplot(x=pts[:, 0], y=pts[:, 1], ax=ax, color=color,
                    levels=8, linewidths=0.8, bw_adjust=1.0,
                    warn_singular=False)
    except Exception:
        ax.scatter(pts[:, 0], pts[:, 1], s=4, color=color, alpha=0.6, linewidths=0)


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args()
    ds = args.dataset
    pfx = "" if ds == "cicids2017" else f"{ds}_"
    CLASSES = CLASSES_BY_DS[ds]
    figs = cfg.results_dir() / "figures"
    rows, labs = pick_rows(ds, CLASSES)
    y = labs[rows]
    print(f"flows: {len(rows)} ({', '.join(f'{c}={int((y == c).sum())}' for c in CLASSES)})")

    for name in EXTRACTORS:
        X = load_nfm(name, ds)[0][rows]
        X = SimpleImputer(strategy="median", keep_empty_features=True).fit_transform(X)
        X = StandardScaler().fit_transform(X)
        if X.shape[1] > 50:
            X = PCA(50, svd_solver="randomized", random_state=SEED).fit_transform(X)
        Z = TSNE(n_components=2, perplexity=30, init="pca",
                 random_state=SEED).fit_transform(X.astype(np.float32))

        fig, ax = plt.subplots(figsize=(2.35, 2.35))
        for cls, color in CLASSES.items():
            kde_contours(ax, Z[y == cls], color)
        ax.set_xticks([]); ax.set_yticks([])
        for s in ax.spines.values():
            s.set_linewidth(0.8)
        ax.grid(False)
        fig.tight_layout(pad=0.2)
        P.savefig_both(fig, figs / f"{pfx}tsne_{name}")
        plt.close(fig)
        print(f"[ok] tsne_{name}", flush=True)

    # legend strip (shared across the subfloats, included above them in LaTeX)
    short = {"Web Attack - Brute Force": "Web Brute Force", "Establish Foothold": "Foothold", "Lateral Movement": "Lateral Movement", "Data Exfiltration": "Data Exfiltration"}
    handles = [Line2D([0], [0], color=c, lw=1.6) for c in CLASSES.values()]
    labels = [short.get(k, k) for k in CLASSES]
    fig = plt.figure(figsize=(7.0, 0.32))
    fig.legend(handles, labels, loc="center", ncol=len(labels), frameon=False,
               fontsize=7.5, handlelength=1.6, columnspacing=1.4)
    P.savefig_both(fig, figs / f"{pfx}tsne_legend")
    plt.close(fig)
    print("[ok] tsne_legend", flush=True)
    print("TSNE DONE", flush=True)


if __name__ == "__main__":
    main()
