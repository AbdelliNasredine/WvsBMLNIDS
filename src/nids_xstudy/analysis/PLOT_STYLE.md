# PLOT_STYLE.md — Figure Style Guide (extracted from reference paper figures)

Rules distilled from 7 reference plots. Enforced by `paper.mplstyle` (rcParams) + `plotting.py` (layout/encoding helpers). Claude Code: every figure in `src/analysis/` MUST use `plt.style.use("paper.mplstyle")` and the helpers; no ad-hoc styling.

## R1 — Layout
- Multi-metric results: **vertically stacked panels sharing the x-axis** (typically 3: e.g., F1 per group / per class family / overall). X tick labels and x-label on the **bottom panel only**. Panel spacing tight (`hspace≈0.12`).
- Figure width = one IEEE column (**3.5 in**); height 4.4–4.8 in for 3 panels, ~2 in for single panels. Export PNG 300 dpi AND PDF (vector) for the paper.
- Numeric-but-uneven x values (4, 10, 20, 40, 100, 200) are plotted **categorically** (equal spacing), never on a log axis.

## R2 — Labels
- Y-labels: `Metric [unit]` — e.g., `F1 All [%]`, `Macro-F1 [%]`. Short; no titles on axes (captions carry the description).
- Sub-figure captions `(a) ...` `(b) ...` set below panels (in LaTeX via subfig); system/tool names in `\texttt{}`.

## R3 — Legend
- **Outside, centered above** the axes; horizontal; **frameless**; font ~7.5 pt; `ncol` = all series if they fit, else 3–4 columns. Never inside the plot area.

## R4 — Bar charts (grouped)
- White background; **horizontal dashed light-gray gridlines only**, drawn behind bars (`axisbelow`).
- Every bar: thin **black edge** (0.8 pt).
- One-factor design: distinct **tab10** colors (green, purple, red, orange, blue, ...).
- The **baseline/reference method** is set apart: **white face + `//` hatch**.
- Two-factor design: **color = factor 1, hatch = factor 2** (`//`, `..`, `xx`); single-color variant (all one color, hatch-only differentiation) acceptable when factor 1 is fixed.
- Y starts at 0 by default. **Crop the y-range only when all values cluster** (e.g., 50–80) and differences are the message — never to exaggerate a favored method.

## R5 — Line charts
- **Triple redundancy** per series: distinct color + distinct marker (o v ^ < > s D) + distinct linestyle (solid/dashed/dash-dot/dotted). Markers ~5.5 pt with black edge. Survives grayscale and colorblind viewing.
- Reference values (upper bounds, non-IID best, prior SOTA): **horizontal black dashed line**, labeled in the legend.
- Same grid/panel rules as R4.

## R6 — Class-distribution plots
- Log-scale y (counts span decades). **Attack classes red, benign green.** Sorted descending. X tick labels rotated 45°, right-anchored. No grid.

## R7 — ROC curves
- X on **symlog** scale so FPR = 0 is plottable; explicit decade ticks `0, 10^-3, 10^-2, 10^-1, 10^0`.
- Dashed black **chance curve** labeled `Chance (AUC=0.5)`.
- Dotted gray **vertical line at the operational FPR** (default 10^-2 — matches the paper's FPR-at-fixed-TPR metric).

## R8 — Typography & color
- Sans-serif (DejaVu/Helvetica), base 8 pt, everything readable at column width without zooming.
- Palette: matplotlib tab10, starting green `#2ca02c`, purple `#9467bd`, red `#d62728`, orange `#ff7f0e`, blue `#1f77b4`.
- Math in labels via mathtext (e.g., `$\mathcal{K}^{old}$`).

## R9 — Consistency contract (for this project)
- A tool/model keeps the SAME color/marker/hatch across ALL figures of the paper (define the mapping once in `plotting.py` and import it; e.g., white-box tools = one hue family per tool, black-box NFMs = a reserved distinct set, baseline = white+hatch).
- Seeds averaged; when spread is shown, use thin black error bars (bars) or lightly shaded bands (lines) — do not clutter.
- Every figure script is deterministic and takes results JSON/CSV paths as input; no hand-edited figures.

## Files
- `paper.mplstyle` — rcParams (fonts, grid, edges, legend, hatch).
- `plotting.py` — helpers: `stacked_panels`, `grouped_bars` (baseline + factorial), `line_series`, `reference_hline`, `class_distribution`, `roc_logx`, `top_legend`, `finish_panels`.
- `demo_*.png` — rendered validation of each rule against the reference look.
