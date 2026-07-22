"""YAF extraction runner: PCAP -> IPFIX -> super_mediator NDJSON -> canonical.

YAF (CERT NetSA) emits biflows with clean per-direction packet/byte counts
(packetTotalCount / reversePacketTotalCount, octetTotalCount /
reverseOctetTotalCount). TCP flags are reported as flag STRINGS/unions
(initialTCPFlags / unionTCPFlags), not per-flag counts, so the canonical flag
columns are left <NA> and the strings are retained as ``tool_``. Timestamps are
UTC ISO-8601 strings (flowStartMilliseconds).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from .. import canonical as C
from .. import config as cfg
from . import _docker
from .base import RunMeta, pcap_fingerprint, write_outputs

TOOL = "yaf"
IMAGE = "nids-xstudy/yaf:2.19.3"


def parse_sm_ndjson(path: Path | str) -> pd.DataFrame:
    """Parse super_mediator NDJSON: one object per line; skip stats lines;
    unwrap a top-level ``flows`` key if present."""
    rows = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "stats" in obj:
                continue
            rows.append(obj.get("flows", obj))
    return pd.json_normalize(rows) if rows else pd.DataFrame()


def _iso_epoch(s: pd.Series) -> pd.Series:
    return pd.to_datetime(s, errors="coerce", utc=True).astype("int64") / 1e9


def to_canonical(y: pd.DataFrame, *, dataset: str, capture: str) -> pd.DataFrame:
    def col(df, name, default=pd.NA):
        return df[name] if name in df.columns else pd.Series([default] * len(df), index=df.index)

    # coalesce IPv4/IPv6, then drop non-flow records (stats/template lines that
    # carry no source IP)
    src = col(y, "sourceIPv4Address").fillna(col(y, "sourceIPv6Address"))
    dst = col(y, "destinationIPv4Address").fillna(col(y, "destinationIPv6Address"))
    valid = src.notna() & dst.notna()
    y = y[valid].reset_index(drop=True)
    src = src[valid].reset_index(drop=True)
    dst = dst[valid].reset_index(drop=True)

    def g(name, default=pd.NA):
        return y[name] if name in y.columns else pd.Series([default] * len(y))

    n = len(y)
    out = pd.DataFrame(index=range(n))
    out["src_ip"] = src.astype("string")
    out["dst_ip"] = dst.astype("string")
    out["src_port"] = pd.to_numeric(g("sourceTransportPort"), errors="coerce")
    out["dst_port"] = pd.to_numeric(g("destinationTransportPort"), errors="coerce")
    out["proto"] = g("protocolIdentifier").map(C.proto_to_number)

    out["t_start"] = _iso_epoch(g("flowStartMilliseconds"))
    out["t_end"] = _iso_epoch(g("flowEndMilliseconds"))
    out["duration"] = out["t_end"] - out["t_start"]

    out["pkts_fwd"] = pd.to_numeric(g("packetTotalCount"), errors="coerce")
    out["pkts_bwd"] = pd.to_numeric(g("reversePacketTotalCount"), errors="coerce")
    out["bytes_fwd"] = pd.to_numeric(g("octetTotalCount"), errors="coerce")
    out["bytes_bwd"] = pd.to_numeric(g("reverseOctetTotalCount"), errors="coerce")
    # YAF gives TCP flag unions/strings, not per-flag counts -> canonical <NA>

    out["tool"] = TOOL
    out["dataset"] = dataset
    out["capture"] = capture
    out["flow_id"] = pd.Series(range(n)).astype("string")

    native = C.prefix_native(y)
    out = pd.concat([out.reset_index(drop=True), native.reset_index(drop=True)], axis=1)
    return C.coerce_schema(out)


def extract(pcap, *, dataset, capture, image=IMAGE, out_path=None, applabel=True) -> Path:
    pcap = Path(pcap)
    if out_path is None:
        out_path = cfg.canonical_dir(dataset, TOOL) / f"{capture}.parquet"
    out_path = Path(out_path)
    out_dir = cfg.extracted_dir(dataset, TOOL) / capture
    out_dir.mkdir(parents=True, exist_ok=True)

    # appLabel DPI segfaults on some packets (e.g. DAPT thursday); disable it there.
    env = None if applabel else {"NO_APPLABEL": "1"}
    proc = _docker.run(image, [f"/pcaps/{pcap.name}", "/out"],
                       pcap=pcap, out_dir=out_dir, workdir="/out", env=env)
    if proc.returncode != 0:
        raise RuntimeError(f"{TOOL} failed (rc={proc.returncode}):\n{proc.stderr[-2000:]}")
    jsons = sorted(out_dir.glob("*.json"))
    if not jsons:
        raise RuntimeError(f"{TOOL} produced no JSON in {out_dir}")
    y = pd.concat([parse_sm_ndjson(j) for j in jsons], ignore_index=True)
    df = to_canonical(y, dataset=dataset, capture=capture)
    meta = RunMeta(
        tool=TOOL, tool_version=image, dataset=dataset, capture=capture,
        pcap_path=str(pcap), pcap_fingerprint=pcap_fingerprint(pcap),
        config={"image": image, "biflow": True, "applabel": True}, n_flows=len(df),
    )
    write_outputs(df, out_path, meta)
    return out_path


def _cli(argv=None):
    ap = argparse.ArgumentParser(description="YAF -> canonical parquet (Docker)")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--capture", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    print("wrote", extract(args.pcap, dataset=args.dataset, capture=args.capture, out_path=args.out))


if __name__ == "__main__":
    _cli()
