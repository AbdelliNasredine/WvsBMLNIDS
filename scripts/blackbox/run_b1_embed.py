#!/usr/bin/env python
"""Phase B1.2 orchestrator: extract frozen embeddings for every model over the
assembled dataset, each in its own conda env (GPU models on ROCm/
Docker). Embeddings cached to the E: data root. Aggregates the RQ-B6 cost table.

    python scripts/blackbox/run_b1_embed.py                 # all models, all days
    python scripts/blackbox/run_b1_embed.py --models yatc etbert
Run from any env (it shells out to each model's env python).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from nids_xstudy import config as cfg  # noqa: E402

_ENVS = Path(r"C:\Users\n8e\miniconda3\envs")
ENV_PY = {
    "raw-cnn": _ENVS / "rocm721-py312" / "python.exe",
    "yatc": _ENVS / "nfm-yatc" / "python.exe",
    "etbert": _ENVS / "nfm-etbert" / "python.exe",
    "netfound": _ENVS / "nfm-netfound" / "python.exe",
}
DEFAULT_MODELS = ["raw-cnn", "yatc", "etbert", "netfound"]
_WORKER = Path(__file__).resolve().parent / "_embed_worker.py"


def cost_table(dataset, cfg_name):
    rows = []
    for model in DEFAULT_MODELS:
        cj = cfg.embeddings_dir(dataset, model, cfg_name) / "_cost.json"
        if cj.exists():
            rows.extend(json.loads(cj.read_text(encoding="utf-8")))
    if not rows:
        return
    # aggregate per model: total flows, mean flows/s, dim, total storage, peak mem
    agg = {}
    for r in rows:
        a = agg.setdefault(r["model"], {"flows": 0, "wall": 0.0, "dim": r["dim"],
                                        "storage": 0.0, "peak": 0.0, "device": r["device"]})
        a["flows"] += r["n_flows"]; a["wall"] += r["wall_s"]
        a["storage"] += r["storage_mb"]
        a["peak"] = max(a["peak"], r.get("peak_gpu_gb") or 0)
    hdr = "| model | device | dim | flows | flows/s | wall (s) | storage (MB) | peak GPU (GB) |"
    sep = "| " + " | ".join(["---"] * 8) + " |"
    body = []
    for m in DEFAULT_MODELS:
        if m in agg:
            a = agg[m]
            fps = round(a["flows"] / a["wall"], 1) if a["wall"] else "-"
            body.append(f"| {m} | {a['device']} | {a['dim']} | {a['flows']:,} | {fps} | "
                        f"{a['wall']:.0f} | {a['storage']:.0f} | {a['peak'] or '-'} |")
    out = cfg.results_dir() / "tables" / "blackbox_cost.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("# RQ-B6 — black-box extraction cost (CIC-IDS2017)\n\n"
                   "Frozen-embedding extraction cost per model, reference assembly.\n\n"
                   + "\n".join([hdr, sep, *body]) + "\n", encoding="utf-8")
    print(f"wrote {out}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    ap.add_argument("--cfg-name", default="reference")
    ap.add_argument("--models", nargs="+", default=DEFAULT_MODELS)
    ap.add_argument("--captures", nargs="+", default=None)
    ap.add_argument("--batch-size", type=int, default=256)
    ap.add_argument("--sample", action="store_true", help="embed the shared subsample")
    args = ap.parse_args(argv)

    # YaTC needs the [32,360] 'yatc' assembly; others use the [32,128] 'reference'.
    per_model_cfg = {"yatc": "yatc"}
    for model in args.models:
        py = ENV_PY[model]
        if not py.exists():
            print(f"[FAIL] {model}: env python missing ({py})", flush=True)
            continue
        cmd = [str(py), str(_WORKER), "--model", model, "--dataset", args.dataset,
               "--cfg-name", per_model_cfg.get(model, args.cfg_name),
               "--batch-size", str(args.batch_size)]
        if args.sample:
            cmd.append("--sample")
        if args.captures:
            cmd += ["--captures", *args.captures]
        print(f"=== embedding {model} (env {py.parent.name}) ===", flush=True)
        subprocess.run(cmd, check=False)
    cost_table(args.dataset, "sample" if args.sample else args.cfg_name)
    print("EMBED DONE", flush=True)


if __name__ == "__main__":
    main()
