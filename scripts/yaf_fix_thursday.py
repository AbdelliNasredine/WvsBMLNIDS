#!/usr/bin/env python
"""Re-extract yaf on the two captures where its appLabel DPI plugin segfaults
(rc=139) on a small number of packets (DAPT2020 thursday-pub / thursday-pvt).

Diagnosis: yaf runs fine WITHOUT --applabel; the crash is content-based in the
app-labeling plugin, independent of packet size. We re-run those captures with
appLabel disabled (NO_APPLABEL=1). All flow-level features are identical; only
the applicationLabel native column is dropped for these two captures.

Requires the yaf image rebuilt from the NO_APPLABEL-aware entrypoint.

    python scripts/yaf_fix_thursday.py
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.extraction import run_yaf  # noqa: E402

DATASET = "dapt20"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--captures", nargs="+", default=["thursday-pub", "thursday-pvt"])
    args = ap.parse_args(argv)
    for cap in args.captures:
        out = cfg.canonical_dir(DATASET, "yaf") / f"{cap}.parquet"
        if out.exists():
            out.unlink()
        print(f"[yaf/no-applabel] {cap} ...", flush=True)
        run_yaf.extract(cfg.pcap_for(DATASET, cap), dataset=DATASET, capture=cap, applabel=False)
        print(f"[ok] yaf {cap} -> {out}", flush=True)
    print("YAF FIX DONE", flush=True)


if __name__ == "__main__":
    main()
