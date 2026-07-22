#!/usr/bin/env python
"""Phase B1: assemble a dataset into per-flow packet sequences, label with the
existing traffic-level engine, and cache to the E: data root. Resumable.

Backend `ppp` (default) uses the PcapPlusPlus Docker assembler; `python` uses the
scapy reference assembler (slow; oracle/fallback). Run in the nids-xstudy env
(scapy + pandas + pyarrow + labeling).

    python scripts/blackbox/run_b1_assemble.py --backend ppp
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import numpy as np  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.assembly.assembler import AssemblyConfig  # noqa: E402
from nids_xstudy.labeling import label_dataset  # noqa: E402


def _assemble(backend, pcap, cfgobj):
    if backend == "ppp":
        from nids_xstudy.assembly.ppp import assemble_ppp
        return assemble_ppp(pcap, cfgobj)
    from nids_xstudy.assembly import assemble
    return assemble(pcap, cfgobj)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    ap.add_argument("--captures", nargs="+", default=None)
    ap.add_argument("--backend", choices=["ppp", "python"], default="ppp")
    ap.add_argument("--cfg-name", default="reference")
    ap.add_argument("--max-pkts", type=int, default=32)
    ap.add_argument("--max-bytes", type=int, default=128)
    args = ap.parse_args(argv)

    caps = args.captures or cfg.captures(args.dataset)
    cfgobj = AssemblyConfig(max_pkts=args.max_pkts, max_bytes=args.max_bytes, name=args.cfg_name)
    outdir = cfg.assembled_dir(args.dataset, args.cfg_name)
    print(f"backend={args.backend} cfg={args.cfg_name}[{args.max_pkts}x{args.max_bytes}] "
          f"out={outdir}", flush=True)

    for cap in caps:
        meta_path = outdir / f"{cap}.meta.parquet"
        img_path = outdir / f"{cap}.images.npy"
        if meta_path.exists() and img_path.exists():
            print(f"[skip] {cap}", flush=True)
            continue
        t0 = time.time()
        meta, imgs = _assemble(args.backend, cfg.pcap_for(args.dataset, cap), cfgobj)
        labeled = label_dataset(meta, args.dataset, cfg, capture=cap)
        labeled.to_parquet(meta_path, index=False)
        np.save(img_path, imgs)
        dt = time.time() - t0
        vc = labeled["label"].value_counts()
        atk = int((labeled["binary_label"].astype("string") == "ATTACK").sum())
        top = ", ".join(f"{k}={v}" for k, v in list(vc.items())[:6])
        print(f"[ok] {cap}: {len(meta):,} flows ({atk:,} attack) in {dt:.0f}s "
              f"| images {imgs.shape} {imgs.nbytes/1e6:.0f}MB | {top}", flush=True)
    print("ASSEMBLE DONE", flush=True)


if __name__ == "__main__":
    main()
