#!/usr/bin/env python
"""Orchestration entrypoint: run an extractor over a capture -> canonical parquet.

    python scripts/extract.py --tool nfstream --dataset cicids2017 --capture Tuesday
    python scripts/extract.py --tool nfstream --dataset cicids2017 --capture all
    python scripts/extract.py --tool zeek --pcap tests/fixtures/smoke.pcap \
        --dataset smoke --capture smoke

NFStream runs natively; the other tools require their Docker image (see
env/docker/README.md).
"""
from __future__ import annotations

import argparse
import time

from nids_xstudy import config as cfg

TOOLS = {
    "nfstream": ("nids_xstudy.extraction.run_nfstream", {}),
    "zeek": ("nids_xstudy.extraction.run_zeek", {}),
    "cicflowmeter-orig": ("nids_xstudy.extraction.run_cicflowmeter", {"variant": "orig"}),
    "cicflowmeter-fixed": ("nids_xstudy.extraction.run_cicflowmeter", {"variant": "fixed"}),
    "argus": ("nids_xstudy.extraction.run_argus", {}),
    "tranalyzer": ("nids_xstudy.extraction.run_tranalyzer", {}),
    "go-flows": ("nids_xstudy.extraction.run_goflows", {}),
    "joy": ("nids_xstudy.extraction.run_joy", {}),
    "yaf": ("nids_xstudy.extraction.run_yaf", {}),
}


def run_one(tool, dataset, capture, pcap, **kw):
    import importlib
    mod_name, fixed = TOOLS[tool]
    mod = importlib.import_module(mod_name)
    pcap = pcap or cfg.pcap_for(dataset, capture)
    t0 = time.time()
    out = mod.extract(pcap, dataset=dataset, capture=capture, **fixed, **kw)
    dt = time.time() - t0
    print(f"[{tool}] {capture}: wrote {out} in {dt/60:.1f} min")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tool", required=True, choices=list(TOOLS))
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--capture", required=True, help="capture name, or 'all'")
    ap.add_argument("--pcap", default=None, help="explicit pcap path (overrides dataset map)")
    args, extra = ap.parse_known_args(argv)

    # pass-through numeric/str options (e.g. --idle-timeout) to the runner
    kw = {}
    it = iter(extra)
    for a in it:
        if a.startswith("--"):
            key = a[2:].replace("-", "_")
            val = next(it, None)
            try:
                val = int(val)
            except (TypeError, ValueError):
                pass
            kw[key] = val

    caps = cfg.captures(args.dataset) if args.capture == "all" else [args.capture]
    for cap in caps:
        run_one(args.tool, args.dataset, cap, args.pcap if args.capture != "all" else None, **kw)


if __name__ == "__main__":
    main()
