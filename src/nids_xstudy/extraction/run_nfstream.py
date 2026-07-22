"""NFStream extraction runner: PCAP -> canonical parquet.

NFStream is pure-Python (bundles nDPI) so this runs natively without Docker.
It is the reference implementation of the runner contract that the Docker-based
tools (Zeek, CICFlowMeter, Argus, Tranalyzer) mirror.

Direction convention: NFStream defines ``src2dst`` as the direction of the flow
initiator (first packet sender), which is exactly our ``fwd`` convention.

Usage
-----
    python -m nids_xstudy.extraction.run_nfstream \
        --pcap E:/CIC-IDS-2017/PCAPs/Tuesday-WorkingHours.pcap \
        --dataset cicids2017 --capture Tuesday

    # or programmatically
    from nids_xstudy.extraction.run_nfstream import extract
    extract(pcap, dataset="cicids2017", capture="Tuesday")
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from .. import canonical as C
from .. import config as cfg
from .base import RunMeta, pcap_fingerprint, write_outputs

TOOL = "nfstream"

# NFStream per-direction flag column stems -> canonical FLAG_NAMES are identical
# (syn, fin, rst, psh, ack, urg, ece, cwr), so mapping is mechanical.


def _nfstream_version() -> str:
    import nfstream
    return getattr(nfstream, "__version__", "unknown")


def to_canonical(ndf: pd.DataFrame, *, dataset: str, capture: str) -> pd.DataFrame:
    """Map an NFStream ``to_pandas()`` frame to the canonical schema.

    All native NFStream columns are retained, prefixed ``tool_`` (the R-native
    feature vector). Core columns are derived from the bidirectional/directional
    NFStream fields.
    """
    n = len(ndf)
    out = pd.DataFrame(index=range(n))

    out["src_ip"] = ndf["src_ip"].astype("string")
    out["dst_ip"] = ndf["dst_ip"].astype("string")
    out["src_port"] = ndf["src_port"]
    out["dst_port"] = ndf["dst_port"]
    out["proto"] = ndf["protocol"]  # IANA L4 protocol number

    # NFStream timestamps are epoch milliseconds (UTC).
    out["t_start"] = ndf["bidirectional_first_seen_ms"].astype("float64") / 1000.0
    out["t_end"] = ndf["bidirectional_last_seen_ms"].astype("float64") / 1000.0
    out["duration"] = ndf["bidirectional_duration_ms"].astype("float64") / 1000.0

    out["pkts_fwd"] = ndf["src2dst_packets"]
    out["pkts_bwd"] = ndf["dst2src_packets"]
    out["bytes_fwd"] = ndf["src2dst_bytes"]
    out["bytes_bwd"] = ndf["dst2src_bytes"]

    for flag in C.FLAG_NAMES:
        fwd_col = f"src2dst_{flag}_packets"
        bwd_col = f"dst2src_{flag}_packets"
        out[f"{flag}_fwd"] = ndf[fwd_col] if fwd_col in ndf else pd.NA
        out[f"{flag}_bwd"] = ndf[bwd_col] if bwd_col in ndf else pd.NA

    out["tool"] = TOOL
    out["dataset"] = dataset
    out["capture"] = capture
    out["flow_id"] = ndf["id"].astype("string") if "id" in ndf else pd.Series(range(n)).astype("string")

    # Retain the full native feature vector, prefixed tool_.
    native = C.prefix_native(ndf)
    out = pd.concat([out.reset_index(drop=True), native.reset_index(drop=True)], axis=1)
    # drop duplicate tool_ columns that duplicate provenance (harmless, but tidy)
    return C.coerce_schema(out)


def extract(
    pcap: Path | str,
    *,
    dataset: str,
    capture: str,
    idle_timeout: int = 120,
    active_timeout: int = 1800,
    accounting_mode: int = 1,  # 1 = IP-layer bytes (excludes L2 framing)
    max_flows: int | None = None,
    out_path: Path | str | None = None,
) -> Path:
    """Extract flows from ``pcap`` with NFStream and write canonical parquet.

    Parameters mirror the aligned-config knobs the study ablates (idle timeout,
    accounting mode). All are recorded in the sidecar meta.
    """
    from nfstream import NFStreamer

    pcap = Path(pcap)
    if out_path is None:
        out_path = cfg.canonical_dir(dataset, TOOL) / f"{capture}.parquet"
    out_path = Path(out_path)

    streamer = NFStreamer(
        source=str(pcap),
        statistical_analysis=True,   # required for per-direction flag/stat features
        idle_timeout=idle_timeout,
        active_timeout=active_timeout,
        accounting_mode=accounting_mode,
        n_dissections=0,             # skip deep dissection payloads (speed); nDPI id still on
    )
    ndf = streamer.to_pandas()
    if max_flows is not None:
        ndf = ndf.head(max_flows)

    df = to_canonical(ndf, dataset=dataset, capture=capture)

    meta = RunMeta(
        tool=TOOL,
        tool_version=_nfstream_version(),
        dataset=dataset,
        capture=capture,
        pcap_path=str(pcap),
        pcap_fingerprint=pcap_fingerprint(pcap),
        config={
            "idle_timeout": idle_timeout,
            "active_timeout": active_timeout,
            "accounting_mode": accounting_mode,
            "statistical_analysis": True,
            "n_dissections": 0,
        },
        n_flows=len(df),
    )
    write_outputs(df, out_path, meta)
    return out_path


def _cli(argv=None):
    ap = argparse.ArgumentParser(description="NFStream -> canonical parquet")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--capture", required=True)
    ap.add_argument("--idle-timeout", type=int, default=120)
    ap.add_argument("--active-timeout", type=int, default=1800)
    ap.add_argument("--accounting-mode", type=int, default=1)
    ap.add_argument("--max-flows", type=int, default=None)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    path = extract(
        args.pcap, dataset=args.dataset, capture=args.capture,
        idle_timeout=args.idle_timeout, active_timeout=args.active_timeout,
        accounting_mode=args.accounting_mode, max_flows=args.max_flows,
        out_path=args.out,
    )
    print(f"wrote {path}")


if __name__ == "__main__":
    _cli()
