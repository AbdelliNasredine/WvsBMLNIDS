#!/usr/bin/env python
"""B1 embedding worker for ONE GPU model. Runs in that model's conda env
(loads its torch). Reads assembled images from E:, embeds on GPU, caches
embeddings to E:, and records cost stats. Invoked by run_b1_embed.py.

    <model-env-python> scripts/blackbox/_embed_worker.py --model yatc
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import numpy as np  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.nfm import get_extractor  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True)
    ap.add_argument("--dataset", default="cicids2017")
    ap.add_argument("--cfg-name", default="reference")
    ap.add_argument("--captures", nargs="+", default=None)
    ap.add_argument("--batch-size", type=int, default=256)
    ap.add_argument("--sample", action="store_true",
                    help="embed only the shared stratified subsample (make_sample.py)")
    args = ap.parse_args(argv)

    import torch
    caps = args.captures or cfg.captures(args.dataset)
    asmdir = cfg.assembled_dir(args.dataset, args.cfg_name)
    outdir = cfg.embeddings_dir(args.dataset, args.model, "sample" if args.sample else args.cfg_name)
    ext = get_extractor(args.model)
    costs = []
    for cap in caps:
        outp = outdir / f"{cap}.npy"
        if outp.exists():
            print(f"[skip] {args.model} {cap}", flush=True)
            continue
        imgpath = asmdir / f"{cap}.images.npy"
        if not imgpath.exists():
            print(f"[wait] {args.model} {cap}: no assembled images yet", flush=True)
            continue
        imgs = np.load(imgpath)
        if args.sample:
            mask = np.load(cfg.assembled_dir(args.dataset, "reference") / f"{cap}.sample_mask.npy")
            imgs = imgs[mask]
        if torch.cuda.is_available():
            torch.cuda.reset_peak_memory_stats()
        t0 = time.time()
        res = ext.embed(imgs, device="cuda", batch_size=args.batch_size)
        dt = time.time() - t0
        np.save(outp, res["embeddings"].astype(np.float32))
        peak_gb = (torch.cuda.max_memory_allocated() / 1e9) if torch.cuda.is_available() else None
        cost = {"model": args.model, "capture": cap, "n_flows": res["n_flows"],
                "dim": res["dim"], "flows_per_s": round(res["n_flows"] / dt, 1) if dt else None,
                "wall_s": round(dt, 1), "peak_gpu_gb": round(peak_gb, 2) if peak_gb else None,
                "storage_mb": round(outp.stat().st_size / 1e6, 1), "device": res["device"],
                "has_nan": res["has_nan"]}
        costs.append(cost)
        print(f"[ok] {json.dumps(cost)}", flush=True)
    if costs:
        (outdir / "_cost.json").write_text(json.dumps(costs, indent=2), encoding="utf-8")
    print(f"WORKER DONE {args.model}", flush=True)


if __name__ == "__main__":
    main()
