"""go-flows extraction runner: PCAP -> CSV -> canonical parquet.

go-flows (CN-TU) is spec-driven; the feature spec lives in specs/go-flows/ and
is mounted at /specs. IMPORTANT LIMITATION: with bidirectional flows go-flows
reports MERGED totals (packetTotalCount/octetTotalCount, tcp*TotalCount), NOT
per-direction counts. We therefore map the merged totals to the ``fwd`` columns
and leave ``bwd`` as <NA>; the merged nature is a documented divergence and the
native values are retained as ``tool_``.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from .. import canonical as C
from .. import config as cfg
from . import _docker
from .base import RunMeta, pcap_fingerprint, write_outputs

TOOL = "go-flows"
IMAGE = "nids-xstudy/go-flows:9f5628c"
SPECS_DIR = cfg.REPO_ROOT / "specs" / "go-flows"

_FLAG_MAP = {"syn": "tcpSynTotalCount", "fin": "tcpFinTotalCount",
             "rst": "tcpRstTotalCount", "psh": "tcpPshTotalCount",
             "ack": "tcpAckTotalCount", "urg": "tcpUrgTotalCount"}


def to_canonical(g: pd.DataFrame, *, dataset: str, capture: str) -> pd.DataFrame:
    n = len(g)
    out = pd.DataFrame(index=range(n))
    out["src_ip"] = g["sourceIPAddress"].astype("string")
    out["dst_ip"] = g["destinationIPAddress"].astype("string")
    out["src_port"] = pd.to_numeric(g["sourceTransportPort"], errors="coerce")
    out["dst_port"] = pd.to_numeric(g["destinationTransportPort"], errors="coerce")
    out["proto"] = g["protocolIdentifier"].map(C.proto_to_number)
    out["t_start"] = pd.to_numeric(g["flowStartMilliseconds"], errors="coerce") / 1000.0
    out["t_end"] = pd.to_numeric(g["flowEndMilliseconds"], errors="coerce") / 1000.0
    out["duration"] = out["t_end"] - out["t_start"]
    # merged totals -> fwd; bwd is <NA> (go-flows has no per-direction counts)
    out["pkts_fwd"] = pd.to_numeric(g["packetTotalCount"], errors="coerce")
    out["pkts_bwd"] = pd.NA
    out["bytes_fwd"] = pd.to_numeric(g["octetTotalCount"], errors="coerce")
    out["bytes_bwd"] = pd.NA
    for flag, col in _FLAG_MAP.items():
        out[f"{flag}_fwd"] = pd.to_numeric(g[col], errors="coerce") if col in g else pd.NA
        out[f"{flag}_bwd"] = pd.NA
    out["tool"] = TOOL
    out["dataset"] = dataset
    out["capture"] = capture
    out["flow_id"] = pd.Series(range(n)).astype("string")
    native = C.prefix_native(g)
    out = pd.concat([out.reset_index(drop=True), native.reset_index(drop=True)], axis=1)
    return C.coerce_schema(out)


def extract(pcap, *, dataset, capture, spec="common", image=IMAGE, out_path=None) -> Path:
    pcap = Path(pcap)
    tool = TOOL if spec == "common" else f"{TOOL}-{spec}"
    if out_path is None:
        out_path = cfg.canonical_dir(dataset, tool) / f"{capture}.parquet"
    out_path = Path(out_path)
    csv_dir = cfg.extracted_dir(dataset, tool) / capture
    csv_dir.mkdir(parents=True, exist_ok=True)

    proc = _docker.run(
        image, [f"/pcaps/{pcap.name}", "/out", spec],
        pcap=pcap, out_dir=csv_dir, workdir="/out",
        extra_mounts=[(SPECS_DIR, "/specs", "ro")],
    )
    if proc.returncode != 0:
        raise RuntimeError(f"{tool} failed (rc={proc.returncode}):\n{proc.stderr[-2000:]}")
    csvs = sorted(csv_dir.glob("*.csv"))
    if not csvs:
        raise RuntimeError(f"{tool} produced no CSV in {csv_dir}")
    g = pd.concat([pd.read_csv(c) for c in csvs], ignore_index=True)
    df = to_canonical(g, dataset=dataset, capture=capture)
    meta = RunMeta(
        tool=tool, tool_version=image, dataset=dataset, capture=capture,
        pcap_path=str(pcap), pcap_fingerprint=pcap_fingerprint(pcap),
        config={"image": image, "spec": spec, "counts": "merged (no per-direction)"},
        n_flows=len(df),
    )
    write_outputs(df, out_path, meta)
    return out_path


def _cli(argv=None):
    ap = argparse.ArgumentParser(description="go-flows -> canonical parquet (Docker)")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--capture", required=True)
    ap.add_argument("--spec", default="common")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    print("wrote", extract(args.pcap, dataset=args.dataset, capture=args.capture,
                           spec=args.spec, out_path=args.out))


if __name__ == "__main__":
    _cli()
