#!/usr/bin/env python
"""Phase B1: stratified subsample of the assembled flows, shared across ALL
models so embeddings stay aligned for the Phase-B2 comparison. netFound's
throughput (~20 flows/s) makes the full 1.85M-flow embedding untenable; we cap
the high-volume classes and keep all rare/attack classes.

Writes per day: a boolean row-mask `<reference>/<cap>.sample_mask.npy` (aligned
to the reference meta row order -- and to any same-order [32,B] assembly, since
segmentation is byte-identical regardless of max_bytes) + the sampled labeled
meta under assembled_dir('sample'). Deterministic (seeded).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402

# per-day per-class caps; classes not listed keep ALL flows (rare/attack).
CAPS_BY_DS = {
    "cicids2017": {"BENIGN": 12000, "PortScan": 20000, "DDoS": 20000, "DoS Hulk": 20000},
    # DAPT: cap only benign per capture; all attack stages are scarce, keep them all.
    "dapt20": {"BENIGN": 12000},
}
SEED = 0


def main(dataset="cicids2017", ref_cfg="reference"):
    CAPS = CAPS_BY_DS.get(dataset, {})
    ref = cfg.assembled_dir(dataset, ref_cfg)
    sdir = cfg.assembled_dir(dataset, "sample")
    rng = np.random.default_rng(SEED)
    total = 0
    for cap in cfg.captures(dataset):
        mp = ref / f"{cap}.meta.parquet"
        if not mp.exists():
            print(f"[skip] {cap}: no reference meta")
            continue
        meta = pd.read_parquet(mp)
        mask = np.zeros(len(meta), dtype=bool)
        for cls, idx in meta.groupby(meta["label"].astype("string")).groups.items():
            idx = np.asarray(idx, dtype=np.int64)
            cn = CAPS.get(str(cls), len(idx))
            if len(idx) > cn:
                idx = rng.choice(idx, cn, replace=False)
            mask[idx] = True
        np.save(ref / f"{cap}.sample_mask.npy", mask)
        meta[mask].reset_index(drop=True).to_parquet(sdir / f"{cap}.meta.parquet", index=False)
        n = int(mask.sum()); total += n
        vc = meta[mask]["label"].value_counts()
        print(f"[ok] {cap}: sampled {n:,} / {len(meta):,} | "
              + ", ".join(f"{k}={v}" for k, v in list(vc.items())[:5]), flush=True)
    print(f"SAMPLE DONE: {total:,} flows total", flush=True)


if __name__ == "__main__":
    main()
