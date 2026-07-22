#!/usr/bin/env python
"""Phase B6: cost-performance Pareto frontier (RQ-B6).

Pairs each extractor's measured END-TO-END throughput (packet -> score) with its
best detection performance (B2 multiclass macro-F1, on the identical 142k flows).
For the NFMs the pipeline is: shared PcapPlusPlus assembly + per-model embedding;
for NFStream it is one native pass (assembly + features). Deliverable: the
deployment-realism Pareto figure + an extended cost table.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.analysis import plotting as P  # noqa: E402

P.use_style()

# measured in B1 (ppp assembly: 1,846,019 flows / 3,129 s) and this session (NFStream slice).
# per-dataset measured throughput (flows/s): assembler + NFStream single-pass.
ASSEMBLY_FPS_BY_DS = {"cicids2017": 590.0, "dapt20": 590.0}
NFSTREAM_FPS_BY_DS = {"cicids2017": 2058.0, "dapt20": 2058.0}
NFMS = ["raw-cnn", "yatc", "etbert", "netfound"]
WB = ["nfstream-common", "nfstream-native"]


def embed_cost(model, dataset):
    """(embed flows/s, dim, GPU GB, storage MB/flow) from the B1 _cost.json."""
    cj = cfg.embeddings_dir(dataset, model, "sample") / "_cost.json"
    rows = json.loads(cj.read_text(encoding="utf-8"))
    flows = sum(r["n_flows"] for r in rows); wall = sum(r["wall_s"] for r in rows)
    dim = rows[0]["dim"]; peak = max((r.get("peak_gpu_gb") or 0) for r in rows)
    storage = sum(r["storage_mb"] for r in rows)
    return flows / wall, dim, peak, storage / flows * 1000  # KB/flow


def best_macro_f1(extractor, dataset):
    """Best head's mean-over-seeds multiclass macro-F1 (matches the B2 report)."""
    d = cfg.results_dir() / "metrics_bb" / dataset
    by_head = {}
    for f in d.glob(f"{extractor}__embedding__*__multiclass__stratified__*.json"):
        r = json.loads(f.read_text())
        by_head.setdefault(r["config"]["model"], []).append(r["metrics"]["macro_f1"])
    return max((sum(v) / len(v) for v in by_head.values()), default=0.0)


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args()
    ds = args.dataset
    pfx = "" if ds == "cicids2017" else f"{ds}_"
    ASSEMBLY_FPS = ASSEMBLY_FPS_BY_DS[ds]; NFSTREAM_FPS = NFSTREAM_FPS_BY_DS[ds]
    rows = []
    for m in NFMS:
        efps, dim, gpu, kbpf = embed_cost(m, ds)
        e2e = 1.0 / (1.0 / ASSEMBLY_FPS + 1.0 / efps)
        rows.append({"extractor": m, "family": "nfm", "hardware": "CPU+GPU",
                     "embed_fps": round(efps, 1), "e2e_fps": round(e2e, 1), "dim": dim,
                     "gpu_gb": round(gpu, 1), "kb_per_flow": round(kbpf, 1),
                     "best_macro_f1": round(best_macro_f1(m, ds), 3)})
    for m in WB:
        rows.append({"extractor": m, "family": "whitebox", "hardware": "CPU",
                     "embed_fps": NFSTREAM_FPS, "e2e_fps": NFSTREAM_FPS,
                     "dim": 9 if m.endswith("common") else 58, "gpu_gb": 0.0,
                     "kb_per_flow": 0.1, "best_macro_f1": round(best_macro_f1(m, ds), 3)})
    df = pd.DataFrame(rows).sort_values("e2e_fps", ascending=False)

    # Pareto frontier: maximize e2e_fps AND best_macro_f1
    pts = df.sort_values("e2e_fps", ascending=False).reset_index(drop=True)
    pareto, best_f1 = [], -1
    for r in pts.itertuples():
        if r.best_macro_f1 > best_f1:
            pareto.append(r.extractor); best_f1 = r.best_macro_f1
    df["pareto"] = df["extractor"].isin(pareto)

    figs = cfg.results_dir() / "figures"; tables = cfg.results_dir() / "tables"
    fig, ax = plt.subplots(figsize=(P.COL_W, 2.4))
    # R9 fixed color+marker per extractor, black edges; the hand-engineered
    # baselines keep their reference look (white / light-gray face).
    for r in df.itertuples():
        face = P.COLOR[r.extractor]
        if r.extractor in P.BASELINES:
            face = "white" if r.extractor == "nfstream-common" else "0.75"
        ax.scatter(r.e2e_fps, 100 * r.best_macro_f1, s=42, c=face,
                   edgecolors="black", linewidths=0.8, zorder=3,
                   marker=P.MARKER[r.extractor])
        ax.annotate(r.extractor, (r.e2e_fps, 100 * r.best_macro_f1), fontsize=6,
                    xytext=(4, 3), textcoords="offset points")
    pf = df[df.pareto].sort_values("e2e_fps")
    ax.plot(pf["e2e_fps"], 100 * pf["best_macro_f1"], color="black",
            linestyle="--", linewidth=1.0, zorder=2, label="Pareto frontier")
    # x = measured continuous throughput -> log scale is allowed (not design points)
    ax.set_xscale("log")
    ax.set_xlabel("Throughput [flows/s]")
    ax.set_ylabel("Best macro-F1 [%]")
    ax.grid(True, axis="y"); ax.set_axisbelow(True)
    P.top_legend(ax, ncol=1)
    P.savefig_both(fig, figs / f"{pfx}b6_pareto"); plt.close(fig)

    cols = ["extractor", "family", "hardware", "e2e_fps", "embed_fps", "dim", "gpu_gb",
            "kb_per_flow", "best_macro_f1", "pareto"]
    h = "| " + " | ".join(cols) + " |"; s = "| " + " | ".join("---" for _ in cols) + " |"
    body = ["| " + " | ".join(str(v) for v in r) + " |" for r in df[cols].itertuples(index=False)]
    md = ["# RQ-B6 cost-performance frontier (CIC-IDS2017, shared 142k flows)", "",
          "End-to-end throughput = shared PcapPlusPlus assembly (590 flows/s) + per-model",
          "embedding (NFMs); NFStream = one native pass. Best macro-F1 from the B2 grid.", "",
          "\n".join([h, s, *body]), "",
          f"**Pareto-optimal:** {', '.join(pareto)}."]
    (tables / f"{pfx}b6_frontier.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(df[cols].to_string(index=False))
    print(f"\nPareto-optimal: {pareto}")
    print(f"wrote {tables/(pfx+'b6_frontier.md')}, {figs/(pfx+'b6_pareto.png')}")


if __name__ == "__main__":
    main()
