#!/usr/bin/env python
"""Cost-vs-performance figures for the black-box comparison, in the project's
seaborn house style (nids_xstudy.analysis.plotting):

  * cost_performance : throughput vs best macro-F1, marker size = GPU memory.
  * cost_resources   : per-flow embedding dimension + storage, by extractor.

Data mirrors the cost table (tab:cost). Writes results/figures/<name>.{png,pdf}.

    python scripts/blackbox/plot_cost_figures.py    # nids-xstudy env
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
import seaborn as sns  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.analysis import plotting as P  # noqa: E402

P.use_style()  # project house style: seaborn whitegrid, sans-serif 8 pt, deep palette

# ---------------- data (mirrors tab:cost) ----------------
df = pd.DataFrame([
    ("NFStream-common", 2058, 0.0,     9, 0.1, 0.813, "White-box"),
    ("NFStream-native", 2058, 0.0,    58, 0.1, 0.837, "White-box"),
    ("raw-bytes CNN",    529, 0.6,   128, 0.5, 0.753, "Black-box"),
    ("YaTC",             208, 12.9,  192, 0.8, 0.842, "Black-box"),
    ("ET-BERT",           47, 4.7,   768, 3.1, 0.858, "Black-box"),
    ("netFound",          23, 10.2, 1024, 4.1, 0.813, "Black-box"),
], columns=["extractor", "flows_s", "gpu_gb", "dim", "kb_flow", "f1", "type"])

# two-category hue -> first two seaborn "deep" colours (the project palette)
_deep = sns.color_palette(P.PALETTE, 2)
palette = {"White-box": _deep[0], "Black-box": _deep[1]}

figs = cfg.results_dir() / "figures"
figs.mkdir(parents=True, exist_ok=True)

# ============================================================
# Figure 1: throughput vs macro-F1, marker size = GPU memory
# ============================================================
fig, ax = plt.subplots(figsize=(P.COL_W, 2.55))
sns.scatterplot(data=df, x="flows_s", y="f1", hue="type", size="gpu_gb",
                sizes=(18, 200), size_norm=(0, 13), palette=palette,
                edgecolor="black", linewidth=0.5, alpha=0.9, ax=ax, zorder=3)

offs = {
    # the two NFStream points sit at the far-right edge, so label them
    # centred directly above/below their (small) markers to stay attached.
    "NFStream-native": (-6,  10, "center"),
    "NFStream-common": (-6, -12, "center"),
    "raw-bytes CNN":   ( 0,   9, "center"),
    "YaTC":            ( 9,   6, "left"),
    "ET-BERT":         ( 9,   3, "left"),
    "netFound":        ( 9,  -3, "left"),
}
for _, r in df.iterrows():
    dx, dy, ha = offs[r.extractor]
    ax.annotate(r.extractor, (r.flows_s, r.f1), textcoords="offset points",
                xytext=(dx, dy), ha=ha, fontsize=7)

ax.set(xscale="log", xlim=(12, 9000), ylim=(0.735, 0.878),
       xlabel="Throughput [flows/s, log]", ylabel="Best macro-F1")

# hue legend (lower left) + a separate GPU-memory size legend (lower right)
h, l = ax.get_legend_handles_labels()
hue_h = [h[l.index("White-box")], h[l.index("Black-box")]]
leg1 = ax.legend(hue_h, ["White-box", "Black-box"], loc="lower left",
                 frameon=False, handletextpad=0.4, borderaxespad=0.2)
ax.add_artist(leg1)
size_for = lambda g: 18 + (200 - 18) * g / 13
h_sz = [plt.scatter([], [], s=size_for(g), facecolor="none", edgecolor="black",
                    linewidth=0.5) for g in (0, 5, 13)]
ax.legend(h_sz, ["0 GB", "5 GB", "13 GB"], title="GPU memory", loc="lower right",
          frameon=False, labelspacing=0.9, handletextpad=0.4, borderaxespad=0.2)

fig.tight_layout(pad=0.3)
P.savefig_both(fig, figs / "cost_performance")
plt.close(fig)

# ============================================================
# Figure 2: per-flow resource profile (embedding dim + storage)
# ============================================================
order = df.extractor.tolist()
fig, axes = plt.subplots(1, 2, figsize=(P.COL_W, 2.0), sharey=True)

sns.barplot(data=df, x="dim", y="extractor", hue="type", order=order,
            palette=palette, edgecolor="black", linewidth=0.4, width=0.62,
            legend=False, ax=axes[0])
axes[0].set(xscale="log", xlim=(6, 4000), xlabel="Embedding dim.", ylabel="")
for i, v in enumerate(df.dim):
    axes[0].text(v * 1.15, i, str(v), va="center", fontsize=6.5)

sns.barplot(data=df, x="kb_flow", y="extractor", hue="type", order=order,
            palette=palette, edgecolor="black", linewidth=0.4, width=0.62,
            legend=False, ax=axes[1])
axes[1].set(xlim=(0, 5.2), xlabel="Storage [KB/flow]", ylabel="")
for i, v in enumerate(df.kb_flow):
    axes[1].text(v + 0.12, i, f"{v:.1f}", va="center", fontsize=6.5)

for a in axes:
    a.grid(axis="y", visible=False)   # keep only the horizontal (x) gridlines
fig.tight_layout(pad=0.3, w_pad=0.8)
P.savefig_both(fig, figs / "cost_resources")
plt.close(fig)

print("wrote cost_performance + cost_resources (.png 300 dpi + .pdf)")
