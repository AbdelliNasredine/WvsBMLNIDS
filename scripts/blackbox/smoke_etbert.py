#!/usr/bin/env python
"""Phase-B0 GPU smoke test for the ET-BERT frozen-embedding extractor.

Runs in the ``nfm-etbert`` ROCm env. Tokenizes the reference assembler's
per-flow packet images with ET-BERT's own hex-bigram BURST tokenization and
embeds them on the GPU, asserting no silent CPU fallback and finite output.

The assembler needs scapy (CPU env), so images are pre-assembled from
``tests/fixtures/smoke.pcap`` in the ``nids-xstudy`` env and passed via ``.npy``.
If ``--images`` is omitted this script will assemble on the fly *iff* scapy is
importable in the current env.

    python scripts/blackbox/smoke_etbert.py --images results/blackbox/tmp/smoke_images.npy

Prints a JSON report. PASS requires: device != cpu, dim > 0, no NaN.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "src"))


def _load_images(images_path: str | None, pcap: str) -> np.ndarray:
    if images_path:
        imgs = np.load(images_path)
    else:
        # Fall back to assembling here (requires scapy in this env).
        from nids_xstudy.assembly import assemble, AssemblyConfig
        _, imgs = assemble(pcap, AssemblyConfig(max_pkts=32, max_bytes=128))
    assert imgs.dtype == np.uint8 and imgs.ndim == 3, f"bad images {imgs.shape} {imgs.dtype}"
    return imgs


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--images", default=None, help="uint8 .npy [N, max_pkts, max_bytes]")
    ap.add_argument("--pcap", default=str(_REPO / "tests" / "fixtures" / "smoke.pcap"))
    ap.add_argument("--batch-size", type=int, default=64)
    args = ap.parse_args(argv)

    imgs = _load_images(args.images, args.pcap)

    from nids_xstudy.nfm.etbert import ETBERTExtractor
    ext = ETBERTExtractor()
    res = ext.embed(imgs, device="cuda", batch_size=args.batch_size)

    ok = (res["device"].lower() != "cpu") and (not res["has_nan"]) and res["dim"] > 0
    report = {
        "model": ext.name,
        "device": res["device"],
        "n_flows": res["n_flows"],
        "dim": res["dim"],
        "flows_per_s": res["flows_per_s"],
        "has_nan": res["has_nan"],
        "provenance": ext.provenance(),
        "PASS": bool(ok),
    }
    print(json.dumps(report, indent=2))
    if not ok:
        raise SystemExit("SMOKE FAILED (device/NaN/dim check)")


if __name__ == "__main__":
    main()
