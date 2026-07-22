"""Re-render the cross-dataset figure from the cached cross_dataset.md table,
in the current (seaborn) plotting style, without retraining. Same layout as
run_cross_dataset.py's figure block. -> results/figures/cross_dataset.{png,pdf}."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.analysis import plotting as P  # noqa: E402

P.use_style()

tables = cfg.results_dir() / "tables"
figs = cfg.results_dir() / "figures"
rows = []
for ln in (tables / "cross_dataset.md").read_text(encoding="utf-8").splitlines():
    if ln.startswith("|") and "---" not in ln and "extractor" not in ln:
        c = [x.strip() for x in ln.strip().strip("|").split("|")]
        # family | extractor | CIC in | CIC->DAPT | DAPT in | DAPT->CIC | collapse
        rows.append((c[1], float(c[2]), float(c[3]), float(c[4]), float(c[5])))

order = [r[0] for r in rows]
indist = np.array([np.mean([r[1], r[3]]) for r in rows])
cross = np.array([np.mean([r[2], r[4]]) for r in rows])

fig, ax = plt.subplots(figsize=(P.DBL_W, 2.6))
P.grouped_bars(ax, order, {"in-distribution": 100 * indist,
                           "cross-dataset": 100 * cross})
ax.set_ylabel("Macro-F1 [%]")
ax.set_xticklabels(order, rotation=45, ha="right", rotation_mode="anchor", fontsize=6)
P.top_legend(ax, ncol=2)
P.savefig_both(fig, figs / "cross_dataset"); plt.close(fig)
print(f"wrote {figs/'cross_dataset.png'} (from cached md; {len(order)} extractors)")
