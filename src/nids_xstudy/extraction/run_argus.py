"""Argus extraction runner: PCAP -> argus biflows -> canonical parquet.

Argus source (s*) = flow initiator = our fwd direction. Argus reports aggregate
TCP flag indicators (``flgs``/``state``), not per-direction flag counts, so the
canonical flag columns are left <NA> and the native fields are retained.

UNVERIFIED end-to-end (Docker daemon was down at authoring time): the field list
and ``ra`` epoch-time flags are per the argus-clients docs; validate the CSV
columns against a smoke pcap once the image is built.
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
IMAGE = "nids-xstudy/argus:latest"


def to_canonical(a: pd.DataFrame, *, dataset: str, capture: str) -> pd.DataFrame:
    n = len(a)
    out = pd.DataFrame(index=range(n))
    out["src_ip"] = a["saddr"].astype("string")
    out["dst_ip"] = a["daddr"].astype("string")
    out["src_port"] = pd.to_numeric(a["sport"], errors="coerce")
    out["dst_port"] = pd.to_numeric(a["dport"], errors="coerce")
    out["proto"] = a["proto"].map(C.proto_to_number)
    out["t_start"] = pd.to_numeric(a["stime"], errors="coerce")
    out["t_end"] = pd.to_numeric(a["ltime"], errors="coerce")
    out["duration"] = pd.to_numeric(a["dur"], errors="coerce")
    out["pkts_fwd"] = pd.to_numeric(a["spkts"], errors="coerce")
    out["pkts_bwd"] = pd.to_numeric(a["dpkts"], errors="coerce")
    out["bytes_fwd"] = pd.to_numeric(a["sbytes"], errors="coerce")
    out["bytes_bwd"] = pd.to_numeric(a["dbytes"], errors="coerce")
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
