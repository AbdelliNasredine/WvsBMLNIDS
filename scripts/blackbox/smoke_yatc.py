#!/usr/bin/env python
"""Phase-B0 GPU smoke test for the YaTC frozen-embedding extractor.

Assembles flows from the fixture PCAP with the reference assembler, rebuilds
YaTC's 40x40 MFR image per flow, and embeds them on the GPU with the pretrained
MAE encoder -- asserting the model actually runs on the accelerator (no silent
CPU fallback), the output is finite, and reporting throughput.

Run under the ROCm ``nfm-yatc`` env (needs scapy + pandas for assembly and the
ROCm torch wheels for the GPU embed):

    conda run -n nfm-yatc python scripts/blackbox/smoke_yatc.py

Prints a JSON report; exits non-zero unless PASS (device != cpu, dim > 0, no NaN).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap", default=str(_ROOT / "tests" / "fixtures" / "smoke.pcap"))
    ap.add_argument("--pool", default="mean", choices=["mean", "cls"])
    ap.add_argument("--batch-size", type=int, default=256)
    ap.add_argument("--images", help="optional pre-assembled uint8 .npy [N,P,L] "
                    "(skips assembly / avoids needing scapy)")
    args = ap.parse_args(argv)

    from nids_xstudy.nfm.yatc import YaTCExtractor, MFR_PKTS, HDR_BYTES, PAY_BYTES, IMG_HW

    if args.images:
        imgs = np.load(args.images)
    else:
        # YaTC needs the first 5 packets and up to 320 header+payload bytes/packet;
        # assemble a superset (>=5 pkts, >=360 IP bytes) so the MFR is complete.
        from nids_xstudy.assembly import assemble, AssemblyConfig
        _, imgs = assemble(args.pcap, AssemblyConfig(max_pkts=8, max_bytes=360))
    assert imgs.dtype == np.uint8 and imgs.ndim == 3, f"bad images {imgs.shape} {imgs.dtype}"

    ext = YaTCExtractor(pool=args.pool)
    res = ext.embed(imgs, device="cuda", batch_size=args.batch_size)

    ok = (res["device"].lower() != "cpu") and (not res["has_nan"]) and res["dim"] > 0
    report = {
        "model": ext.name,
        "device": res["device"],
        "n_flows": res["n_flows"],
        "dim": res["dim"],
        "flows_per_s": res["flows_per_s"],
        "has_nan": res["has_nan"],
        "pool": args.pool,
        "mfr_input": {"packets": MFR_PKTS, "header_bytes": HDR_BYTES,
                      "payload_bytes": PAY_BYTES, "image": [IMG_HW, IMG_HW]},
        "checkpoint_sha256": ext.checkpoint_hash,
        "random_init": ext.random_init,
        "provenance": ext.provenance(),
        "PASS": bool(ok),
    }
    print(json.dumps(report, indent=2))
    if not ok:
        raise SystemExit("SMOKE FAILED (device/NaN/dim check)")


if __name__ == "__main__":
    main()
