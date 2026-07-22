"""CICFlowMeter extraction runner (original + DistriNet-fixed variants).

Both variants are the Java CICFlowMeter run in Docker; they differ only in the
source repo/commit (RQ4 "bug impact": the Engelen fork fixes TCP flag counting,
FIN/RST flow termination, and duplicate/timeout handling). This runner parses
either variant's ``*_Flow.csv`` into the canonical schema.

CICFlowMeter limitations captured here (themselves cross-tool divergences):
* Per-direction flag counts exist only for PSH and URG (``Fwd/Bwd PSH/URG
  Flags``). SYN/FIN/RST/ACK/CWR/ECE are reported only as flow totals, so the
  canonical per-direction flag columns are left <NA> for those; the totals are
  retained as ``tool_*`` columns for the RQ4 analysis.
* The ``Timestamp`` column is a formatted local-time string; we run the
  container with TZ=UTC and parse day-first so t_start is UTC epoch. This MUST
  be cross-checked against NFStream/Zeek t_start on the same pcap (Phase 2).
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

import pandas as pd

from .. import canonical as C
from .. import config as cfg
from . import _docker
from .base import RunMeta, pcap_fingerprint, write_outputs

TOOL_BY_VARIANT = {"orig": "cicflowmeter-orig", "fixed": "cicflowmeter-fixed"}
IMAGE_BY_VARIANT = {
    "orig": "nids-xstudy/cicflowmeter-orig:v4",
    "fixed": "nids-xstudy/cicflowmeter-fixed:distrinet",
}


def _norm(col: str) -> str:
    return re.sub(r"[^a-z0-9]", "", col.lower())


# normalized-header -> canonical core column. Multiple header spellings across
# CICFlowMeter versions map to the same canonical field.
_MAP = {
    "srcip": "src_ip", "sourceip": "src_ip",
    "dstip": "dst_ip", "destinationip": "dst_ip",
    "srcport": "src_port", "sourceport": "src_port",
    "dstport": "dst_port", "destinationport": "dst_port",
    "protocol": "proto",
    "totalfwdpacket": "pkts_fwd", "totalfwdpackets": "pkts_fwd", "totfwdpkts": "pkts_fwd",
    "totalbwdpackets": "pkts_bwd", "totalbackwardpackets": "pkts_bwd", "totbwdpkts": "pkts_bwd",
    "totallengthoffwdpacket": "bytes_fwd", "totallengthoffwdpackets": "bytes_fwd", "totlenfwdpkts": "bytes_fwd",
    "totallengthofbwdpacket": "bytes_bwd", "totallengthofbwdpackets": "bytes_bwd", "totlenbwdpkts": "bytes_bwd",
    "fwdpshflags": "psh_fwd", "bwdpshflags": "psh_bwd",
    "fwdurgflags": "urg_fwd", "bwdurgflags": "urg_bwd",
    "flowid": "flow_id",
}


def to_canonical(raw: pd.DataFrame, *, dataset: str, capture: str, tool: str) -> pd.DataFrame:
    norm2orig = {_norm(c): c for c in raw.columns}
    n = len(raw)
    out = pd.DataFrame(index=range(n))

    def col(canon_key: str):
        for nrm, canon in _MAP.items():
            if canon == canon_key and nrm in norm2orig:
                return raw[norm2orig[nrm]]
        return None

    for canon_key in ["src_ip", "dst_ip", "src_port", "dst_port", "proto",
                      "pkts_fwd", "pkts_bwd", "bytes_fwd", "bytes_bwd",
                      "psh_fwd", "psh_bwd", "urg_fwd", "urg_bwd", "flow_id"]:
        s = col(canon_key)
        if s is not None:
            out[canon_key] = s

    out["src_ip"] = out["src_ip"].astype("string")
    out["dst_ip"] = out["dst_ip"].astype("string")
    out["proto"] = out["proto"].map(C.proto_to_number)

    # timestamp (flow start) -> UTC epoch; duration is microseconds.
    # The original fork prints dd/MM/yyyy (12h, AM/PM) -> dayfirst=True; the
    # DistriNet fixed fork prints ISO yyyy-MM-dd HH:MM:SS.ffffff -> dayfirst
    # would flip month/day (July 4 -> April 7). Detect the format from a sample.
    ts_col = norm2orig.get("timestamp")
    if ts_col:
        s = raw[ts_col].astype("string")
        sample = s.dropna().iloc[0] if s.notna().any() else ""
        iso = bool(re.match(r"^\s*\d{4}-", str(sample)))
        t_start = pd.to_datetime(s, dayfirst=not iso, utc=True,
                                 errors="coerce").astype("int64") / 1e9
    else:
        t_start = pd.Series([pd.NA] * n)
    dur_col = norm2orig.get("flowduration")
    dur_us = pd.to_numeric(raw[dur_col], errors="coerce") if dur_col else pd.Series([0.0] * n)
    out["t_start"] = t_start
    # CICFlowMeter can emit a few negative flow durations (a timestamp/ordering
    # artifact); clip to 0 so t_end >= t_start. The raw value is kept in
    # tool_flow_duration for anyone studying the artifact.
    out["duration"] = (dur_us / 1e6).clip(lower=0)
    out["t_end"] = out["t_start"] + out["duration"]

    # SYN/FIN/RST/ACK/CWR/ECE: only flow totals available -> per-direction <NA>
    for flag in ["syn", "fin", "rst", "ack", "ece", "cwr"]:
        out[f"{flag}_fwd"] = pd.NA
        out[f"{flag}_bwd"] = pd.NA

    out["tool"] = tool
    out["dataset"] = dataset
    out["capture"] = capture
    if "flow_id" not in out or out["flow_id"].isna().all():
        out["flow_id"] = pd.Series(range(n)).astype("string")

    native = C.prefix_native(raw)
    out = pd.concat([out.reset_index(drop=True), native.reset_index(drop=True)], axis=1)
    return C.coerce_schema(out)


def extract(
    pcap: Path | str,
    *,
    dataset: str,
    capture: str,
    variant: str = "orig",
    image: str | None = None,
    out_path: Path | str | None = None,
) -> Path:
    if variant not in TOOL_BY_VARIANT:
        raise ValueError(f"variant must be one of {list(TOOL_BY_VARIANT)}")
    tool = TOOL_BY_VARIANT[variant]
    image = image or IMAGE_BY_VARIANT[variant]
    pcap = Path(pcap)
    if out_path is None:
        out_path = cfg.canonical_dir(dataset, tool) / f"{capture}.parquet"
    out_path = Path(out_path)
    csv_dir = cfg.extracted_dir(dataset, tool) / capture
    csv_dir.mkdir(parents=True, exist_ok=True)

    # container entrypoint: CICFlowMeter Cmd <pcap> <outdir> -> <name>_Flow.csv
    proc = _docker.run(
        image, [f"/pcaps/{pcap.name}", "/out"],
        pcap=pcap, out_dir=csv_dir, workdir="/out",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"{tool} failed (rc={proc.returncode}):\n{proc.stderr[-2000:]}")

    csvs = sorted(csv_dir.glob("*_Flow.csv")) or sorted(csv_dir.glob("*.csv"))
    if not csvs:
        raise RuntimeError(f"{tool} produced no CSV in {csv_dir}")
    raw = pd.concat([pd.read_csv(c) for c in csvs], ignore_index=True)
    df = to_canonical(raw, dataset=dataset, capture=capture, tool=tool)

    meta = RunMeta(
        tool=tool, tool_version=image, dataset=dataset, capture=capture,
        pcap_path=str(pcap), pcap_fingerprint=pcap_fingerprint(pcap),
        config={"variant": variant, "image": image, "tz": "UTC"},
        n_flows=len(df),
    )
    write_outputs(df, out_path, meta)
    return out_path


def _cli(argv=None):
    ap = argparse.ArgumentParser(description="CICFlowMeter -> canonical parquet (Docker)")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--capture", required=True)
    ap.add_argument("--variant", choices=["orig", "fixed"], default="orig")
    ap.add_argument("--image", default=None)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    print("wrote", extract(args.pcap, dataset=args.dataset, capture=args.capture,
                           variant=args.variant, image=args.image, out_path=args.out))


if __name__ == "__main__":
    _cli()
