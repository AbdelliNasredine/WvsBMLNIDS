#!/usr/bin/env python
"""Phase-1 driver: extract capture days for a set of tools -> canonical parquet.

Resumable (skips captures whose parquet already exists) and fault-tolerant (a
failure on one tool/day is logged and does not stop the rest). Run several
instances in parallel, grouped by tool speed:

    python scripts/run_phase1_extract.py --tools argus go-flows yaf joy
    python scripts/run_phase1_extract.py --tools cicflowmeter-orig cicflowmeter-fixed
"""
from __future__ import annotations

import argparse
import importlib
import time
import traceback

from nids_xstudy import config as cfg

# tool -> (runner module, extract kwargs, canonical dir name)
TOOLS = {
    "nfstream": ("run_nfstream", {}, "nfstream"),
    "zeek": ("run_zeek", {}, "zeek"),
    "tranalyzer": ("run_tranalyzer", {}, "tranalyzer"),
    "argus": ("run_argus", {}, "argus"),
    "cicflowmeter-orig": ("run_cicflowmeter", {"variant": "orig"}, "cicflowmeter-orig"),
    "cicflowmeter-fixed": ("run_cicflowmeter", {"variant": "fixed"}, "cicflowmeter-fixed"),
    "go-flows": ("run_goflows", {}, "go-flows"),
    "yaf": ("run_yaf", {}, "yaf"),
    "joy": ("run_joy", {}, "joy"),
}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tools", nargs="+", required=True, choices=list(TOOLS))
    ap.add_argument("--dataset", default="cicids2017")
    ap.add_argument("--captures", nargs="+", default=None)
    args = ap.parse_args(argv)

    captures = args.captures or cfg.captures(args.dataset)
    ok, fail, skip = 0, 0, 0
    for tool in args.tools:
        mod_name, kwargs, dirname = TOOLS[tool]
        mod = importlib.import_module(f"nids_xstudy.extraction.{mod_name}")
        for cap in captures:
            p = cfg.canonical_dir(args.dataset, dirname) / f"{cap}.parquet"
            if p.exists():
                print(f"[skip] {tool} {cap} (exists)", flush=True)
                skip += 1
                continue
            pcap = cfg.pcap_for(args.dataset, cap)
            t0 = time.time()
            try:
                mod.extract(pcap, dataset=args.dataset, capture=cap, **kwargs)
                print(f"[ok] {tool} {cap} in {(time.time()-t0)/60:.1f} min", flush=True)
                ok += 1
            except Exception as e:  # noqa: BLE001 - keep going on failure
                print(f"[FAIL] {tool} {cap} after {(time.time()-t0)/60:.1f} min: {e}", flush=True)
                traceback.print_exc()
                fail += 1
    print(f"DONE tools={args.tools}: {ok} ok, {fail} failed, {skip} skipped", flush=True)


if __name__ == "__main__":
    main()
