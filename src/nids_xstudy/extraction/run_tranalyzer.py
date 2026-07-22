"""Tranalyzer2 extraction runner: PCAP -> _flows.txt -> canonical parquet.

Tranalyzer's basicStats gives per-direction Snt/Rcvd counts (Snt = flow
direction = our fwd). Its tcpFlags plugin reports aggregate flag bitfields, not
per-direction counts, so canonical flag columns are left <NA> (native retained).

Directionality caveat: Tranalyzer can emit separate A/B records for a
connection; canonical treats each record independently here. Pairing A/B into a
single bidirectional flow is a documented TODO for the flow-alignment phase.

UNVERIFIED end-to-end (Docker was down at authoring); validate columns on the
smoke pcap once the image is built.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from .. import canonical as C
from .. import config as cfg
from . import _docker
from .base import RunMeta, pcap_fingerprint, write_outputs

TOOL = "tranalyzer"
IMAGE = "nids-xstudy/tranalyzer:0.9.4"

# Tranalyzer column name -> canonical core column. The 'A' record is the
# initiator-oriented bidirectional flow (pktsSnt=fwd, pktsRcvd=bwd); Tranalyzer
# also emits a duplicate 'B' reverse record per bidirectional connection, which
# we drop (see to_canonical) to get one flow per connection like the other
# tools. Bytes are L7/payload bytes (l7Bytes*) — a documented byte-semantics
# divergence vs NFStream/Zeek IP-layer bytes.
_MAP = {
    "srcIP": "src_ip", "dstIP": "dst_ip",
    "srcPort": "src_port", "dstPort": "dst_port", "l4Proto": "proto",
    "timeFirst": "t_start", "timeLast": "t_end", "duration": "duration",
    "pktsSnt": "pkts_fwd", "pktsRcvd": "pkts_bwd",
    "l7BytesSnt": "bytes_fwd", "l7BytesRcvd": "bytes_bwd",
    "flowInd": "flow_id",
}


def parse_flows_txt(path: Path | str) -> pd.DataFrame:
    """Parse a Tranalyzer _flows.txt (tab-separated, %-prefixed header row)."""
    path = Path(path)
    df = pd.read_csv(path, sep="\t", dtype=str, engine="python")
    df.columns = [c.lstrip("%").strip() for c in df.columns]
    return df


def to_canonical(t: pd.DataFrame, *, dataset: str, capture: str) -> pd.DataFrame:
    # Keep only the initiator-oriented 'A' records; drop Tranalyzer's duplicate
    # 'B' reverse records so there is one flow per connection. Records with no
    # direction column (non-bidirectional) are kept.
    if "dir" in t.columns:
        t = t[t["dir"].astype("string").str.strip().isin(["A", ""]) | t["dir"].isna()]
        t = t.reset_index(drop=True)
    n = len(t)
    out = pd.DataFrame(index=range(n))
    for src, canon in _MAP.items():
        if src in t.columns:
            out[canon] = t[src]
    out["src_ip"] = out.get("src_ip", pd.Series([pd.NA] * n)).astype("string")
    out["dst_ip"] = out.get("dst_ip", pd.Series([pd.NA] * n)).astype("string")
    for numcol in ["src_port", "dst_port", "t_start", "t_end", "duration",
                   "pkts_fwd", "pkts_bwd", "bytes_fwd", "bytes_bwd"]:
        if numcol in out:
            out[numcol] = pd.to_numeric(out[numcol], errors="coerce")
    if "proto" in out:
        out["proto"] = out["proto"].map(C.proto_to_number)
    out["tool"] = TOOL
    out["dataset"] = dataset
    out["capture"] = capture
    if "flow_id" in out:
        out["flow_id"] = out["flow_id"].astype("string")
    native = C.prefix_native(t)
    out = pd.concat([out.reset_index(drop=True), native.reset_index(drop=True)], axis=1)
    return C.coerce_schema(out)


def extract(pcap, *, dataset, capture, image=IMAGE, out_path=None) -> Path:
    pcap = Path(pcap)
    if out_path is None:
        out_path = cfg.canonical_dir(dataset, TOOL) / f"{capture}.parquet"
    out_path = Path(out_path)
    out_dir = cfg.extracted_dir(dataset, TOOL) / capture
    out_dir.mkdir(parents=True, exist_ok=True)

    proc = _docker.run(image, [f"/pcaps/{pcap.name}", "/out"],
                       pcap=pcap, out_dir=out_dir, workdir="/out")
    if proc.returncode != 0:
        raise RuntimeError(f"tranalyzer failed (rc={proc.returncode}):\n{proc.stderr[-2000:]}")
    flows = sorted(out_dir.glob("*_flows.txt"))
    if not flows:
        raise RuntimeError(f"tranalyzer produced no _flows.txt in {out_dir}")
    t = pd.concat([parse_flows_txt(f) for f in flows], ignore_index=True)
    df = to_canonical(t, dataset=dataset, capture=capture)
    meta = RunMeta(
        tool=TOOL, tool_version=image, dataset=dataset, capture=capture,
        pcap_path=str(pcap), pcap_fingerprint=pcap_fingerprint(pcap),
        config={"image": image, "plugins": ["basicFlow", "basicStats", "tcpFlags", "pktSIATHisto"]},
        n_flows=len(df),
    )
    write_outputs(df, out_path, meta)
    return out_path


def _cli(argv=None):
    ap = argparse.ArgumentParser(description="Tranalyzer -> canonical parquet (Docker)")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--capture", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    print("wrote", extract(args.pcap, dataset=args.dataset, capture=args.capture, out_path=args.out))


if __name__ == "__main__":
    _cli()
