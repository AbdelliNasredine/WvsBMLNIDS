#!/usr/bin/env python
"""Targeted re-extraction for specific (tool, capture) pairs.

Used to repair W1 gaps: re-run a tool on repaired (de-truncated) pcaps, or
force-overwrite after a mapping fix. Reuses the run_phase1_extract tool registry.

    # zeek/yaf on the de-truncated copies of the two truncated captures
    python scripts/reextract.py --dataset dapt20 --tool zeek --captures monday-pub wednesday-pub --repaired --force
    # argus everywhere after the duration-mapping fix
    python scripts/reextract.py --dataset dapt20 --tool argus --force
"""
from __future__ import annotations

import argparse
import importlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids_xstudy import config as cfg  # noqa: E402
from run_phase1_extract import TOOLS  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="dapt20")
    ap.add_argument("--tool", required=True, choices=list(TOOLS))
    ap.add_argument("--captures", nargs="+", default=None)
    ap.add_argument("--repaired", action="store_true",
                    help="prefer <pcap_root>/../pcap-repaired/<file> when it exists")
    ap.add_argument("--force", action="store_true", help="overwrite existing canonical parquet")
    args = ap.parse_args(argv)

    mod_name, kwargs, dirname = TOOLS[args.tool]
    mod = importlib.import_module(f"nids_xstudy.extraction.{mod_name}")
    caps = args.captures or cfg.captures(args.dataset)
    repaired_dir = cfg.pcap_root(args.dataset).parent / "pcap-repaired"

    ok = fail = skip = 0
    for cap in caps:
        out = cfg.canonical_dir(args.dataset, dirname) / f"{cap}.parquet"
        if out.exists() and not args.force:
            print(f"[skip] {args.tool} {cap} (exists)", flush=True)
            skip += 1
            continue
        pcap = cfg.pcap_for(args.dataset, cap)
        if args.repaired:
            rp = repaired_dir / pcap.name
            if rp.exists():
                pcap = rp
                print(f"[repaired-src] {cap} -> {rp}", flush=True)
        if out.exists():
            out.unlink()
        t0 = time.time()
        try:
            mod.extract(pcap, dataset=args.dataset, capture=cap, **kwargs)
            print(f"[ok] {args.tool} {cap} in {(time.time()-t0)/60:.1f} min", flush=True)
            ok += 1
        except Exception as e:  # noqa: BLE001
            print(f"[FAIL] {args.tool} {cap} after {(time.time()-t0)/60:.1f} min: {e}", flush=True)
            fail += 1
    print(f"DONE {args.tool}: {ok} ok, {fail} failed, {skip} skipped", flush=True)


if __name__ == "__main__":
    main()
