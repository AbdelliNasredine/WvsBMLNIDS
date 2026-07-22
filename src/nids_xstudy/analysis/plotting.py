"""Seaborn-based plotting helpers for every paper figure.

Usage in a generator::

    from nids_xstudy.analysis import plotting as P
    P.use_style()
    fig, ax = plt.subplots(figsize=(P.COL_W, P.PANEL_H))
    P.grouped_bars(ax, tools, {"R-common": v1, "R-native": v2}, ...)
    P.top_legend(ax)
    P.savefig_both(fig, figs / "my_figure")     # -> .png (300 dpi) + .pdf

Styling is delegated to seaborn (``sns.set_theme``): the "deep" palette,
whitegrid background and despined seaborn look apply to every figure. Colours
come from the seaborn palette by series order rather than a fixed per-tool
mapping. Two conventions are kept because they are *semantic*: heatmaps use the
sequential ``Blues`` colormap, and the benign class stays green in class-coloured
plots (assigned by the caller). The COLOR / MARKER / HATCH / LINESTYLE dicts
below survive only as fallbacks for the few figures that still draw on a raw
axes (per-class split bars, the Pareto scatter, the critical-difference diagrams).

Kept invariants: single IEEE column width (COL_W) with DBL_W the wide-figure
exception; uneven numeric x (timeouts, k-shot) plotted categorically; y-labels
read ``Metric [unit]`` with no axes titles; the legend sits frameless above the
axes; both raster (.png 300 dpi) and vector (.pdf) are exported.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

# ---------------------------------------------------------------- R1 geometry
COL_W = 3.5      # one IEEE column [in]
DBL_W = 7.16     # double column [in] -- ONLY for the 15-column per-class heatmap
PANEL_H = 2.0    # default single-panel height [in]

STYLE_PATH = Path(__file__).resolve().parent / "paper.mplstyle"

#: seaborn palette used across all figures (colour by series order).
PALETTE = "deep"

#: IEEE-specific rc overrides layered on top of the seaborn theme: base 8 pt
#: DejaVu sans, frameless legend, 300 dpi raster export with a tight bbox.
IEEE_RC = {
    "figure.dpi": 150,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02,
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans", "Helvetica", "Arial"],
    "font.size": 8,
    "axes.labelsize": 8,
    "axes.titlesize": 8,
    "xtick.labelsize": 7.5,
    "ytick.labelsize": 7.5,
    "legend.fontsize": 7.5,
    "legend.title_fontsize": 7.5,
    "legend.frameon": False,
    "mathtext.fontset": "dejavusans",
    "grid.linestyle": "--",
    "grid.linewidth": 0.6,
}


def use_style() -> None:
    """Activate the seaborn theme + IEEE rc overrides. Call once per generator."""
    sns.set_theme(context="paper", style="whitegrid", palette=PALETTE, rc=IEEE_RC)


# ------------------------------------------------------- R9 consistency contract
# tab10-ish palette in the mandated order: green, purple, red, orange, blue, ...
_G, _P, _R, _O, _B = "#2ca02c", "#9467bd", "#d62728", "#ff7f0e", "#1f77b4"
_BR, _PK, _OL, _CY = "#8c564b", "#e377c2", "#bcbd22", "#17becf"

#: Fixed color per tool/model across ALL figures. The white-box tools and the
#: black-box set never share a figure, so the five primary hues are reused
#: across the two disjoint families; within any one figure all series differ.
COLOR = {
    # 9 white-box flow extractors
    "nfstream": _G, "zeek": _P, "tranalyzer": _R,
    "cicflowmeter-orig": _O, "cicflowmeter-fixed": _B,
    "argus": _BR, "go-flows": _PK, "yaf": _OL, "joy": _CY,
    # black-box NFMs
    "raw-cnn": _G, "yatc": _P, "etbert": _R, "netfound": _O,
    # hand-engineered baselines (reference series: black / gray)
    "nfstream-common": "black", "nfstream-native": "#666666",
}

#: Fixed marker per tool/model (R5 set: o v ^ < > s D, extended P X for 9 tools).
MARKER = {
    "nfstream": "o", "zeek": "v", "tranalyzer": "^",
    "cicflowmeter-orig": "<", "cicflowmeter-fixed": ">",
    "argus": "s", "go-flows": "D", "yaf": "P", "joy": "X",
    "raw-cnn": "o", "yatc": "v", "etbert": "^", "netfound": "<",
    "nfstream-common": "s", "nfstream-native": "D",
}

#: Fixed hatch per tool/model when it appears as a bar series.
HATCH = {
    "nfstream": "//", "zeek": "..", "tranalyzer": "xx",
    "cicflowmeter-orig": "\\\\", "cicflowmeter-fixed": "oo",
    "argus": "++", "go-flows": "//", "yaf": "..", "joy": "xx",
    "raw-cnn": "//", "yatc": "..", "etbert": "xx", "netfound": "\\\\",
    "nfstream-common": "//", "nfstream-native": "//",
}

#: Fixed linestyle per tool/model in line charts (R5 triple redundancy).
LINESTYLE = {
    "nfstream": "-", "zeek": "--", "tranalyzer": "-.",
    "cicflowmeter-orig": ":", "cicflowmeter-fixed": "-",
    "argus": "--", "go-flows": "-.", "yaf": ":", "joy": "-",
    "raw-cnn": "-", "yatc": "--", "etbert": "-.", "netfound": ":",
    "nfstream-common": "--", "nfstream-native": "--",
}

#: Reference/baseline series: white face + '//' hatch (bars), black/gray dashed (lines).
BASELINES = {"nfstream-common", "nfstream-native"}
BASELINE_FACE = "white"
BASELINE_HATCH = "//"

# Cycles for series that are NOT R9 entities (factors, regimes, match categories).
CYCLE_COLORS = [_G, _P, _R, _O, _B, _BR, _PK, _OL, _CY]
CYCLE_HATCHES = ["//", "..", "xx", "\\\\", "oo", "++"]
CYCLE_MARKERS = ["o", "v", "^", "<", ">", "s", "D"]
CYCLE_LINESTYLES = ["-", "--", "-.", ":"]

HEATMAP_CMAP = "Blues"  # blue theme; sequential + luminance-monotonic (grayscale-safe)


def series_color(name: str, i: int) -> str:
    return COLOR.get(name, CYCLE_COLORS[i % len(CYCLE_COLORS)])


def series_marker(name: str, i: int) -> str:
    return MARKER.get(name, CYCLE_MARKERS[i % len(CYCLE_MARKERS)])


def series_linestyle(name: str, i: int) -> str:
    return LINESTYLE.get(name, CYCLE_LINESTYLES[i % len(CYCLE_LINESTYLES)])


# ----------------------------------------------------------------- R3 legend
def _default_ncol(n: int) -> int:
    if n <= 5:
        return n
    return 3 if n % 3 == 0 else 4


def top_legend(fig_or_ax, handles=None, labels=None, ncol=None, y=1.02, **kw):
    """R3: frameless horizontal legend OUTSIDE, centered ABOVE the axes."""
    if handles is None or labels is None:
        if hasattr(fig_or_ax, "get_legend_handles_labels"):   # Axes
            handles, labels = fig_or_ax.get_legend_handles_labels()
        else:                                                  # Figure
            hs, ls = [], []
            for ax in fig_or_ax.axes:
                h, l = ax.get_legend_handles_labels()
                for hi, li in zip(h, l):
                    if li not in ls:
                        hs.append(hi); ls.append(li)
            handles, labels = hs, ls
    ncol = ncol or _default_ncol(len(labels))
    anchor_y = y if hasattr(fig_or_ax, "get_legend_handles_labels") else 1.0
    return fig_or_ax.legend(handles, labels, loc="lower center",
                            bbox_to_anchor=(0.5, anchor_y), ncol=ncol,
                            frameon=False, fontsize=7.5,
                            borderaxespad=0.0, **kw)


# ------------------------------------------------------------------- bars
def grouped_bars(ax, x_labels, series, yerr=None, colors=None, hatches=None,
                 baseline=(), group_width=0.82, ylim=None, rotate=0):
    """Grouped bars on a CATEGORICAL x, drawn with ``sns.barplot``.

    series : dict {name: values} aligned with x_labels.
    yerr   : optional dict {name: errors} -> thin black error bars overlaid on
             the seaborn bars.
    colors/hatches : optional lists overriding the seaborn palette / adding a
                     hatch per series (two-factor designs: color = factor 1,
                     hatch = factor 2).
    baseline : iterable of series names rendered white + '//' (names in
               BASELINES are always treated as reference series).
    """
    names = list(series)
    cats = [str(x) for x in x_labels]
    long = pd.DataFrame(
        [{"x": cats[j], "series": name, "val": series[name][j]}
         for name in names for j in range(len(cats))])
    palette = ({name: colors[i] for i, name in enumerate(names)}
               if colors is not None else
               dict(zip(names, sns.color_palette(PALETTE, len(names)))))
    sns.barplot(data=long, x="x", y="val", hue="series", ax=ax,
                order=cats, hue_order=names, palette=palette, errorbar=None,
                edgecolor="black", linewidth=0.8, saturation=1.0)
    # per-series hatch / baseline restyle + error bars, using the actual bar
    # geometry seaborn produced (one BarContainer per hue, in hue_order).
    for i, name in enumerate(names):
        cont = ax.containers[i]
        is_base = name in baseline or name in BASELINES
        for patch in cont:
            if is_base:
                patch.set_facecolor(BASELINE_FACE)
                patch.set_hatch(BASELINE_HATCH)
            elif hatches is not None and hatches[i]:
                patch.set_hatch(hatches[i])
        if yerr is not None and yerr.get(name) is not None:
            xc = [p.get_x() + p.get_width() / 2 for p in cont]
            yc = [p.get_height() for p in cont]
            ax.errorbar(xc, yc, yerr=list(yerr[name]), fmt="none",
                        ecolor="black", elinewidth=0.8, capsize=1.5, capthick=0.8)
    if rotate:
        for lbl in ax.get_xticklabels():
            lbl.set_rotation(rotate); lbl.set_ha("right")
            lbl.set_rotation_mode("anchor")
    ax.set_xlabel(""); ax.set_ylabel("")   # callers set their own labels
    ax.set_ylim(*ylim) if ylim is not None else ax.set_ylim(0, None)
    if ax.get_legend() is not None:
        ax.get_legend().remove()           # top_legend() manages the legend
    ax.set_axisbelow(True)
    return list(ax.containers)


# ------------------------------------------------------------------ lines
def line_series(ax, x_labels, series, bands=None, colors=None, markers=None,
                linestyles=None):
    """Line chart on a CATEGORICAL x (never log-x for uneven design points).

    Colours come from the seaborn palette by series order; each series also
    gets a distinct marker so the lines stay readable. Markers are borderless.
    BASELINES are drawn dashed. bands: optional {name: (lo, hi)} shaded spread.
    """
    xs = np.arange(len(x_labels))
    names = list(series)
    palette = sns.color_palette(PALETTE, len(names))
    handles = []
    for i, name in enumerate(names):
        color = colors[i] if colors is not None else palette[i]
        marker = markers[i] if markers is not None else CYCLE_MARKERS[i % len(CYCLE_MARKERS)]
        ls = linestyles[i] if linestyles is not None else "-"
        if name in BASELINES:
            ls = "--"
        vals = np.asarray(series[name], dtype="float64")
        h, = ax.plot(xs, vals, label=name, color=color, marker=marker,
                     linestyle=ls, markeredgewidth=0)
        if bands and name in bands:
            lo, hi = bands[name]
            ax.fill_between(xs, np.asarray(lo, dtype="float64"),
                            np.asarray(hi, dtype="float64"),
                            color=color, alpha=0.15, linewidth=0)
        handles.append(h)
    ax.set_xticks(xs, [str(x) for x in x_labels])
    ax.set_xlim(-0.25, len(x_labels) - 0.75)
    ax.set_axisbelow(True)
    return handles


def reference_hline(ax, y, label=None):
    """R5: horizontal black dashed reference line, labeled in the legend."""
    return ax.axhline(y, color="black", linestyle="--", linewidth=1.0,
                      label=label)


# ---------------------------------------------------------------- heatmaps
def style_heatmap(ax, data, row_labels, col_labels, vmin=None, vmax=None,
                  fmt="{:.0f}", cbar_label=None, annot_size=6.5, xrot=45,
                  cmap=HEATMAP_CMAP):
    """Heatmap via ``sns.heatmap``: sequential Blues colormap, numeric
    annotations with seaborn's contrast-adaptive text colour, an optional
    colorbar, no gridlines and no title. NaN cells are left blank.
    Returns the Axes."""
    arr = np.asarray(data, dtype="float64")
    annot = np.empty(arr.shape, dtype=object)
    for i in range(arr.shape[0]):
        for j in range(arr.shape[1]):
            annot[i, j] = "" if np.isnan(arr[i, j]) else fmt.format(arr[i, j])
    sns.heatmap(arr, ax=ax, cmap=cmap, vmin=vmin, vmax=vmax,
                annot=annot, fmt="", annot_kws={"size": annot_size},
                xticklabels=col_labels, yticklabels=row_labels,
                linewidths=0, cbar=cbar_label is not None,
                cbar_kws={"label": cbar_label, "pad": 0.02} if cbar_label else None)
    ax.grid(False)
    ax.set_xticklabels(col_labels, rotation=xrot, ha="right",
                       rotation_mode="anchor", fontsize=7)
    ax.set_yticklabels(row_labels, rotation=0, fontsize=7)
    if cbar_label is not None:
        ax.collections[0].colorbar.ax.tick_params(labelsize=7)
    return ax


# ------------------------------------------------------------------- export
def savefig_both(fig, path_without_ext):
    """R1: export BOTH raster (.png, 300 dpi) and vector (.pdf), same basename."""
    p = Path(str(path_without_ext))
    if p.suffix.lower() in (".png", ".pdf"):
        p = p.with_suffix("")
    p.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(p.with_suffix(".png"), dpi=300)
    fig.savefig(p.with_suffix(".pdf"))
    return p
