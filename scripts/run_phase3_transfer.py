#!/usr/bin/env python
"""Run the RQ2 cross-tool transfer matrix + heatmap + table."""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.analysis import plotting as P  # noqa: E402
from nids_xstudy.ml.transfer import transfer_matrix  # noqa: E402

P.use_style()

TOOLS = ["nfstream", "zeek", "tranalyzer", "cicflowmeter-orig", "cicflowmeter-fixed",
         "argus", "go-flows", "yaf", "joy"]
SHORT = {"nfstream": "nfs", "zeek": "zeek", "tranalyzer": "tran", "cicflowmeter-orig": "cfm-o",
         "cicflowmeter-fixed": "cfm-f", "argus": "argus", "go-flows": "goflw", "yaf": "yaf", "joy": "joy"}


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args()
    ds = args.dataset
    pfx = "" if ds == "cicids2017" else f"{ds}_"
    rows = transfer_matrix(TOOLS, model="rf", seed=0, dataset=ds)
    df = pd.DataFrame(rows)
    mat = df.pivot(index="train", columns="test", values="macro_f1").reindex(index=TOOLS, columns=TOOLS)

    figs = cfg.results_dir() / "figures"; figs.mkdir(parents=True, exist_ok=True)
    tables = cfg.results_dir() / "tables"; tables.mkdir(parents=True, exist_ok=True)

    data = mat.to_numpy()
    fig, ax = plt.subplots(figsize=(P.COL_W, 2.9))
    P.style_heatmap(ax, 100 * data, row_labels=[SHORT[t] for t in TOOLS],
                    col_labels=[SHORT[t] for t in TOOLS], vmin=50, vmax=100,
                    cbar_label="Macro-F1 [%]", annot_size=5.5)
    ax.set_xlabel("Test tool B"); ax.set_ylabel("Train tool A")
    P.savefig_both(fig, figs / f"{pfx}transfer_matrix"); plt.close(fig)

    diag = np.diag(data)
    offdiag = data[~np.eye(len(TOOLS), dtype=bool)]
    head = "| train \\ test | " + " | ".join(SHORT[t] for t in TOOLS) + " |"
    sep = "| --- " * (len(TOOLS) + 1) + "|"
    body = ["| " + SHORT[TOOLS[i]] + " | " + " | ".join(f"{data[i,j]:.3f}" for j in range(len(TOOLS))) + " |"
            for i in range(len(TOOLS))]
    md = ["# RQ2 cross-tool transfer matrix (binary macro-F1)", "",
          "Train a RandomForest on tool A's R-common features, test on tool B's.",
          f"Mean diagonal (within-tool): **{diag.mean():.3f}**; mean off-diagonal",
          f"(transfer): **{offdiag.mean():.3f}**; mean drop **{diag.mean()-offdiag.mean():.3f}**.",
          "A large drop means the same features carry tool-specific values.", "",
          "\n".join([head, sep, *body]), ""]
    (tables / f"{pfx}transfer_matrix.md").write_text("\n".join(md), encoding="utf-8")
    print(f"within-tool mean {diag.mean():.3f} | transfer mean {offdiag.mean():.3f} | drop {diag.mean()-offdiag.mean():.3f}")
    print(f"wrote {tables/(pfx+'transfer_matrix.md')}, {figs/(pfx+'transfer_matrix.png')}")


if __name__ == "__main__":
    main()
