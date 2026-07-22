#!/usr/bin/env python
"""Phase-B0 GPU smoke test for a black-box extractor.

Runs in the ROCm env. Loads a pre-assembled uint8 packet-image array (produced
by the assembler in the CPU env) and embeds it, asserting the model runs on the
GPU (no silent CPU fallback), the output is finite, and reporting throughput.

    python scripts/blackbox/smoke_embed.py --images <images.npy> --model raw-cnn
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

MODELS = {}


def _get(model: str):
    if model == "raw-cnn":
        from nids_xstudy.nfm.raw_cnn import RawCNNExtractor
        return RawCNNExtractor()
    raise SystemExit(f"unknown model {model!r} (available: raw-cnn)")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--images", required=True, help="uint8 .npy [N, max_pkts, max_bytes]")
    ap.add_argument("--model", default="raw-cnn")
    ap.add_argument("--batch-size", type=int, default=256)
    args = ap.parse_args(argv)

    imgs = np.load(args.images)
    assert imgs.dtype == np.uint8 and imgs.ndim == 3, f"bad images {imgs.shape} {imgs.dtype}"
    ext = _get(args.model)
    res = ext.embed(imgs, device="cuda", batch_size=args.batch_size)

    ok = (res["device"].lower() != "cpu") and (not res["has_nan"]) and res["dim"] > 0
    report = {"model": args.model, "device": res["device"], "n_flows": res["n_flows"],
              "dim": res["dim"], "flows_per_s": res["flows_per_s"], "has_nan": res["has_nan"],
              "provenance": ext.provenance(), "PASS": bool(ok)}
    print(json.dumps(report, indent=2))
    if not ok:
        raise SystemExit("SMOKE FAILED (device/NaN/dim check)")


if __name__ == "__main__":
    main()
