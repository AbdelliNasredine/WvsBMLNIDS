#!/usr/bin/env python
"""Phase-4a timeout ablation: re-extract timeout-configurable tools at idle
timeouts {15,60,120,600}s on attack-heavy days. Isolates flow-segmentation
policy from tool identity — if divergence shrinks when timeouts are aligned,
the timeout policy (not the tool) drove it.

Extracts to <data_root>/ablation/timeout/<tool>_t<T>/<day>.parquet. Resumable.
"""
from __future__ import annotations

import argparse
import json
import time
import traceback

from nids_xstudy import config as cfg
from nids_xstudy.extraction import run_goflows, run_nfstream

TIMEOUTS = [15, 60, 120, 600]
# attack-heavy captures per dataset (segmentation-sensitive traffic).
DAYS_BY_DS = {
    "cicids2017": ["Wednesday", "Friday"],
    # DAPT: wednesday-pub (dirbuster foothold, many short flows) + thursday-pvt
    # (the 89M-packet SSH flood -> the most timeout-sensitive capture in the study).
    "dapt20": ["wednesday-pub", "thursday-pvt"],
}
SPECS = cfg.REPO_ROOT / "specs" / "go-flows"


def goflows_spec(T: int) -> str:
    base = json.loads((SPECS / "common.json").read_text(encoding="utf-8"))
    base["idle_timeout"] = T
    (SPECS / f"common_t{T}.json").write_text(json.dumps(base, indent=2), encoding="utf-8")
    return f"common_t{T}"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    ap.add_argument("--captures", nargs="+", default=None)
    args = ap.parse_args(argv)
    ds = args.dataset
    days = args.captures or DAYS_BY_DS.get(ds, [])
    ABL = cfg.data_root() / "ablation" / "timeout" / ds
    for T in TIMEOUTS:
        spec = goflows_spec(T)
        for day in days:
            pcap = cfg.pcap_for(ds, day)
            for tool, fn, kw in [
                ("nfstream", run_nfstream.extract, {"idle_timeout": T, "active_timeout": 1800}),
                ("go-flows", run_goflows.extract, {"spec": spec}),
            ]:
                out = ABL / f"{tool}_t{T}" / f"{day}.parquet"
                out.parent.mkdir(parents=True, exist_ok=True)
                if out.exists():
                    print(f"[skip] {tool} t{T} {day}", flush=True)
                    continue
                t0 = time.time()
                try:
                    fn(pcap, dataset=ds, capture=day, out_path=out, **kw)
                    print(f"[ok] {tool} t{T} {day} ({time.time()-t0:.0f}s)", flush=True)
                except Exception as e:  # noqa: BLE001
                    print(f"[FAIL] {tool} t{T} {day}: {e}", flush=True)
                    traceback.print_exc()
    print("TIMEOUT ABLATION DONE", flush=True)


if __name__ == "__main__":
    main()
