"""Validation harness for the Dockerized PcapPlusPlus flow assembler (ppp).

A. Smoke   : run assemble_ppp on tests/fixtures/smoke.pcap, check GROUND_TRUTH.
B. Oracle  : run the scapy reference assemble() and assemble_ppp() on a real
             pcap slice; confirm identical flow counts + per-flow agreement on
             5-tuple, t_start, pkts_fwd/bwd, and the first 40 image bytes of pkt0.
C. Speed   : report flows/sec and pkt/sec for the ppp run on the slice.

Usage:
    python scripts/blackbox/validate_ppp.py            # A only
    python scripts/blackbox/validate_ppp.py <slice.pcap>   # A + B + C
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO))

from nids_xstudy.assembly.assembler import assemble, ASSEMBLY_DEFAULTS  # noqa: E402
from nids_xstudy.assembly.ppp import assemble_ppp  # noqa: E402
from tests.fixtures.smoke import GROUND_TRUTH, build_pcap, PCAP_PATH  # noqa: E402

FIVE = ["src_ip", "src_port", "dst_ip", "dst_port", "proto"]


def _key(row):
    return (row.src_ip, int(row.src_port), row.dst_ip, int(row.dst_port), int(row.proto))


def validate_a() -> bool:
    print("=" * 70)
    print("VALIDATION A -- smoke fixture")
    print("=" * 70)
    if not PCAP_PATH.exists():
        build_pcap(PCAP_PATH)
    meta, images = assemble_ppp(PCAP_PATH)
    ok = True

    n = len(meta)
    exp_n = GROUND_TRUTH["n_flows_idle120"]
    print(f"n_flows = {n} (expected {exp_n})  {'OK' if n == exp_n else 'FAIL'}")
    ok &= (n == exp_n)

    def find(sip, sport, dport, proto):
        m = meta[(meta.src_ip == sip) & (meta.src_port == sport)
                 & (meta.dst_port == dport) & (meta.proto == proto)]
        return m

    http = find("10.0.0.10", 40001, 80, 6)
    if len(http) == 1:
        r = http.iloc[0]
        good = (r.pkts_fwd == 6 and r.pkts_bwd == 4)
        print(f"HTTP  10.0.0.10:40001->:80  pkts_fwd={r.pkts_fwd} pkts_bwd={r.pkts_bwd} "
              f"(expect 6/4)  {'OK' if good else 'FAIL'}")
        ok &= good
    else:
        print(f"HTTP flow lookup FAIL (found {len(http)})"); ok = False

    rst = find("10.0.0.12", 40010, 8080, 6)
    if len(rst) == 1:
        r = rst.iloc[0]
        good = (r.pkts_fwd == 3 and r.pkts_bwd == 2)
        print(f"RST   10.0.0.12:40010->:8080  pkts_fwd={r.pkts_fwd} pkts_bwd={r.pkts_bwd} "
              f"(expect 3/2)  {'OK' if good else 'FAIL'}")
        ok &= good
    else:
        print(f"RST flow lookup FAIL (found {len(rst)})"); ok = False

    scan = meta[(meta.src_ip == "10.0.0.99") & (meta.src_port == 40003)]
    scan_ok = (len(scan) == 20
               and (scan.pkts_fwd == 1).all() and (scan.pkts_bwd == 0).all()
               and sorted(scan.dst_port.tolist()) == list(range(1, 21)))
    print(f"SCAN  10.0.0.99:40003  n={len(scan)} (expect 20) each 1fwd/0bwd, "
          f"dst_ports 1..20  {'OK' if scan_ok else 'FAIL'}")
    ok &= scan_ok

    lng = meta[(meta.src_ip == "10.0.0.11") & (meta.src_port == 40002)
               & (meta.dst_port == 443) & (meta.proto == 6)]
    lng_ok = (len(lng) == 2)
    print(f"LONG  10.0.0.11:40002->:443  n_segments={len(lng)} (expect 2)  "
          f"{'OK' if lng_ok else 'FAIL'}")
    ok &= lng_ok

    # Bonus: exact cross-check ppp vs scapy oracle on the smoke fixture.
    o_meta, o_images = assemble(PCAP_PATH)
    same_count = len(o_meta) == len(meta)
    imgs_equal = same_count and np.array_equal(o_images, images)
    cols = ["src_ip", "src_port", "dst_ip", "dst_port", "proto", "n_pkts",
            "n_bytes", "pkts_fwd", "pkts_bwd", "bytes_fwd", "bytes_bwd", "seq_len"]
    meta_equal = same_count and o_meta[cols].reset_index(drop=True).equals(
        meta[cols].reset_index(drop=True))
    print(f"ppp==oracle on smoke: images_equal={imgs_equal} meta_equal={meta_equal}")
    ok &= imgs_equal and meta_equal

    print(f"\nVALIDATION A: {'PASS' if ok else 'FAIL'}\n")
    return ok


def validate_bc(slice_path: Path) -> bool:
    print("=" * 70)
    print(f"VALIDATION B/C -- real slice: {slice_path}")
    print("=" * 70)
    if not slice_path.exists():
        print(f"slice not found: {slice_path} -- skipping B/C")
        return False

    t0 = time.perf_counter()
    o_meta, o_images = assemble(slice_path)
    t_oracle = time.perf_counter() - t0

    t0 = time.perf_counter()
    p_meta, p_images = assemble_ppp(slice_path)
    t_ppp = time.perf_counter() - t0

    n_o, n_p = len(o_meta), len(p_meta)
    print(f"flow count: oracle={n_o}  ppp={n_p}  "
          f"{'MATCH' if n_o == n_p else 'MISMATCH'}")

    total_pkts = int(p_meta.n_pkts.sum())
    print(f"\n--- C: throughput (ppp) ---")
    print(f"ppp wall time     : {t_ppp:.2f} s  (includes docker run overhead)")
    print(f"oracle wall time  : {t_oracle:.2f} s  (scapy)")
    print(f"IP packets (sum n_pkts) : {total_pkts}")
    print(f"ppp flows/sec     : {n_p / t_ppp:,.0f}")
    print(f"ppp pkt/sec       : {total_pkts / t_ppp:,.0f}")
    print(f"oracle pkt/sec    : {total_pkts / t_oracle:,.0f}")
    print(f"speedup (pkt/sec) : {t_oracle / t_ppp:.1f}x")

    # --- B: per-flow agreement (matched by 5-tuple + t_start, robust to any
    #        rare sort-order tie between the two independent sorts) ---
    print(f"\n--- B: per-flow agreement ---")
    o = o_meta.reset_index(drop=True)
    p = p_meta.reset_index(drop=True)

    def sig(row):
        # 5-tuple + t_start rounded to 10us: unique per flow (splits differ in
        # t_start by >> 10us; concurrent same-5-tuple flows cannot coexist).
        return (row.src_ip, int(row.src_port), row.dst_ip, int(row.dst_port),
                int(row.proto), round(float(row.t_start), 5))

    p_index = {sig(p.iloc[i]): i for i in range(len(p))}

    checked = 0
    matched = 0
    mism = []
    for i in range(len(o)):
        ro = o.iloc[i]
        j = p_index.get(sig(ro))
        checked += 1
        if j is None:
            if len(mism) < 10:
                mism.append((i, _key(ro), None, "no-match", None, None, None))
            continue
        rp = p.iloc[j]
        ts_ok = abs(float(ro.t_start) - float(rp.t_start)) <= 2e-6
        dir_ok = (int(ro.pkts_fwd) == int(rp.pkts_fwd)
                  and int(ro.pkts_bwd) == int(rp.pkts_bwd))
        img_ok = np.array_equal(o_images[i, 0, :40], p_images[j, 0, :40])
        if ts_ok and dir_ok and img_ok:
            matched += 1
        elif len(mism) < 10:
            mism.append((i, _key(ro), _key(rp), True, ts_ok, dir_ok, img_ok))

    rate = 100.0 * matched / checked if checked else 0.0
    print(f"flows checked     : {checked}")
    print(f"flows fully matched (5tuple+t_start+pkts_fwd/bwd+img40): {matched}")
    print(f"match rate        : {rate:.2f}%")
    if mism:
        print("first mismatches (idx, oracle_key, ppp_key, 5tuple,ts,dir,img40):")
        for m in mism:
            print("  ", m)

    ok = (n_o == n_p) and (matched == checked) and checked >= 20
    print(f"\nVALIDATION B: {'PASS' if ok else 'FAIL'}\n")
    return ok


if __name__ == "__main__":
    a_ok = validate_a()
    if len(sys.argv) > 1:
        bc_ok = validate_bc(Path(sys.argv[1]))
    else:
        print("(no slice path given -> skipping B/C)")
        bc_ok = None
    print("=" * 70)
    print(f"SUMMARY: A={'PASS' if a_ok else 'FAIL'} "
          f"B/C={'PASS' if bc_ok else ('SKIP' if bc_ok is None else 'FAIL')}")
