#!/usr/bin/env python
"""Repair a tail-truncated classic libpcap file by dropping the final incomplete
record. DAPT2020 captures were stopped mid-packet by tcpdump, leaving a short
final record; lenient tools (nfstream/zeek/joy/cicflowmeter/go-flows) ignore it,
but yaf aborts. This rewrites the file keeping only the complete records, so yaf
reads exactly what the other tools effectively processed.

    python scripts/repair_truncated_pcap.py --dataset dapt20 --captures monday-pub thursday-pvt
    python scripts/repair_truncated_pcap.py --dataset dapt20            # all captures

Repaired files go to <pcap_root>/../pcap-repaired/<filename>. Files that are NOT
truncated are reported and skipped (no copy).
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids_xstudy import config as cfg  # noqa: E402


def repair(src: Path, dst: Path) -> tuple[int, int, bool]:
    """Copy complete records from src to dst. Returns (n_records, dropped, truncated)."""
    with open(src, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise ValueError("file smaller than a pcap global header")
        # little-endian magic d4c3b2a1 (usec) — DAPT is classic LE
        records = []
        truncated = False
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                if len(rh) > 0:
                    truncated = True
                break
            ts_sec, ts_usec, caplen, wirelen = struct.unpack("<IIII", rh)
            body = f.read(caplen)
            if len(body) < caplen:
                truncated = True   # incomplete final packet
                break
            records.append(rh + body)
    if not truncated:
        return len(records), 0, False
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(dst, "wb") as out:
        out.write(gh)
        for r in records:
            out.write(r)
    return len(records), 1, True


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="dapt20")
    ap.add_argument("--captures", nargs="+", default=None)
    args = ap.parse_args(argv)

    caps = args.captures or cfg.captures(args.dataset)
    outdir = cfg.pcap_root(args.dataset).parent / "pcap-repaired"
    for cap in caps:
        src = cfg.pcap_for(args.dataset, cap)
        dst = outdir / src.name
        try:
            n, dropped, trunc = repair(src, dst)
        except Exception as e:  # noqa: BLE001
            print(f"[FAIL] {cap}: {e}", flush=True)
            continue
        if trunc:
            print(f"[repaired] {cap}: kept {n:,} records, dropped {dropped} truncated tail -> {dst}", flush=True)
        else:
            print(f"[clean] {cap}: {n:,} records, not truncated (no copy)", flush=True)


if __name__ == "__main__":
    main()
