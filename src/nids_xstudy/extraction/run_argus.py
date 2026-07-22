"""Argus extraction runner: PCAP -> argus biflows -> canonical parquet.

Argus source (s*) = flow initiator = our fwd direction. Argus reports aggregate
TCP flag indicators (``flgs``/``state``), not per-direction flag counts, so the
canonical flag columns are left <NA> and the native fields are retained.

Uses Argus 5.0.3 built from openargus source (env/docker/argus). The older
Ubuntu argus 3.0.8.2 package emitted count-less INT records for multi-packet
flows in batch pcap mode; the source build fixes this (verified on the smoke
pcap: HTTP flow reports SrcPkts=6/DstPkts=4). racluster aggregates argus'
periodic status records into one final record per flow.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from .. import canonical as C
from .. import config as cfg
from . import _docker
from .base import RunMeta, pcap_fingerprint, write_outputs

TOOL = "argus"
IMAGE = "nids-xstudy/argus:5"


# racluster header (from `-s stime ltime dur proto saddr sport daddr dport
# spkts dpkts sbytes dbytes state flgs`) -> canonical core column.
_MAP = {
    "SrcAddr": "src_ip", "DstAddr": "dst_ip",
    "Sport": "src_port", "Dport": "dst_port", "Proto": "proto",
    "StartTime": "t_start", "LastTime": "t_end", "Dur": "duration",
    "SrcPkts": "pkts_fwd", "DstPkts": "pkts_bwd",
    "SrcBytes": "bytes_fwd", "DstBytes": "bytes_bwd",
}

# argus non-flow record types (management/status) to drop
_NON_FLOW_PROTO = {"man", "rtp", "arp", ""}


def to_canonical(a: pd.DataFrame, *, dataset: str, capture: str) -> pd.DataFrame:
    a = a.copy()
    a.columns = [c.strip() for c in a.columns]
    # drop argus management/status records (proto=man, all-zero endpoints)
    proto_l = a["Proto"].astype("string").str.strip().str.lower()
    keep = ~proto_l.isin(_NON_FLOW_PROTO) & ~a["SrcAddr"].astype("string").str.strip().isin(["0", "0.0.0.0", ""])
    a = a[keep].reset_index(drop=True)

    n = len(a)
    out = pd.DataFrame(index=range(n))
    out["src_ip"] = a["SrcAddr"].astype("string").str.strip()
    out["dst_ip"] = a["DstAddr"].astype("string").str.strip()
    out["src_port"] = pd.to_numeric(a["Sport"], errors="coerce")
    out["dst_port"] = pd.to_numeric(a["Dport"], errors="coerce")
    out["proto"] = a["Proto"].map(C.proto_to_number)
    out["t_start"] = pd.to_numeric(a["StartTime"], errors="coerce")
    _dur = pd.to_numeric(a["Dur"], errors="coerce").fillna(0.0)
    # LastTime can be blank for single-record flows; fall back to start+dur.
    lt = pd.to_numeric(a["LastTime"], errors="coerce")
    out["t_end"] = lt.fillna(out["t_start"] + _dur)
    # Derive duration from the authoritative timestamps: argus reports Dur, stime
    # and ltime independently and Dur != (ltime - stime) for some flows (rounding
    # / active-vs-wall duration), which violates the canonical invariant. The
    # timestamps win; Dur is redundant.
    out["duration"] = (out["t_end"] - out["t_start"]).clip(lower=0.0)
    out["pkts_fwd"] = pd.to_numeric(a["SrcPkts"], errors="coerce")
    out["pkts_bwd"] = pd.to_numeric(a["DstPkts"], errors="coerce")
    out["bytes_fwd"] = pd.to_numeric(a["SrcBytes"], errors="coerce")
    out["bytes_bwd"] = pd.to_numeric(a["DstBytes"], errors="coerce")
    # per-direction flag counts not available from argus -> <NA>
    out["tool"] = TOOL
    out["dataset"] = dataset
    out["capture"] = capture
    out["flow_id"] = pd.Series(range(n)).astype("string")
    native = C.prefix_native(a)
    out = pd.concat([out.reset_index(drop=True), native.reset_index(drop=True)], axis=1)
    return C.coerce_schema(out)


def extract(pcap, *, dataset, capture, mode="bi", image=IMAGE, out_path=None) -> Path:
    pcap = Path(pcap)
    tool = TOOL if mode == "bi" else f"{TOOL}-uni"
    if out_path is None:
        out_path = cfg.canonical_dir(dataset, tool) / f"{capture}.parquet"
    out_path = Path(out_path)
    out_dir = cfg.extracted_dir(dataset, tool) / capture
    out_dir.mkdir(parents=True, exist_ok=True)

    proc = _docker.run(image, [f"/pcaps/{pcap.name}", "/out", mode],
                       pcap=pcap, out_dir=out_dir, workdir="/out")
    if proc.returncode != 0:
        raise RuntimeError(f"argus failed (rc={proc.returncode}):\n{proc.stderr[-2000:]}")
    csvs = sorted(out_dir.glob("*.argus.csv"))
    if not csvs:
        raise RuntimeError(f"argus produced no CSV in {out_dir}")
    a = pd.concat([pd.read_csv(c) for c in csvs], ignore_index=True)
    df = to_canonical(a, dataset=dataset, capture=capture)
    meta = RunMeta(
        tool=tool, tool_version=image, dataset=dataset, capture=capture,
        pcap_path=str(pcap), pcap_fingerprint=pcap_fingerprint(pcap),
        config={"image": image, "mode": mode}, n_flows=len(df),
    )
    write_outputs(df, out_path, meta)
    return out_path


def _cli(argv=None):
    ap = argparse.ArgumentParser(description="Argus -> canonical parquet (Docker)")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--capture", required=True)
    ap.add_argument("--mode", choices=["bi", "uni"], default="bi")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    print("wrote", extract(args.pcap, dataset=args.dataset, capture=args.capture,
                           mode=args.mode, out_path=args.out))


if __name__ == "__main__":
    _cli()
