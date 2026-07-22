"""Joy extraction runner: PCAP -> gzipped NDJSON -> canonical (+derived stats).

Joy (Cisco) emits per-flow JSON with 5-tuple, times, per-direction byte/packet
counts, and a per-packet ``packets`` sequence ({b: bytes, dir: '>'/'<', ipt: ms}).
Joy does NOT emit statistical features directly; we DERIVE per-direction packet-
size stats and inter-arrival-time stats from the sequence here. This derivation
is part of the study methodology (kept separate from Joy's own output, stored as
``tool_derived_*`` columns) and is unit-tested on the smoke PCAP.

Direction: Joy '>' = source->dest (fwd), '<' = dest->source (bwd). Joy has no
TCP flag counts -> canonical flag columns are <NA>. The per-packet array is
capped (num_pkts=200) so derived stats reflect up to the first 200 packets.
"""
from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .. import canonical as C
from .. import config as cfg
from . import _docker
from .base import RunMeta, pcap_fingerprint, write_outputs

TOOL = "joy"
IMAGE = "nids-xstudy/joy:4.4.1"


def _stats(vals, prefix: str) -> dict:
    a = np.asarray(vals, dtype="float64")
    if a.size == 0:
        return {f"{prefix}_{s}": np.nan for s in ("mean", "std", "min", "max", "n")}
    return {
        f"{prefix}_mean": float(a.mean()), f"{prefix}_std": float(a.std()),
        f"{prefix}_min": float(a.min()), f"{prefix}_max": float(a.max()),
        f"{prefix}_n": int(a.size),
    }


def _derive(packets: list) -> dict:
    """Per-direction packet-size + overall IAT stats from Joy's packet sequence."""
    fwd = [p.get("b", 0) for p in packets if p.get("dir") == ">"]
    bwd = [p.get("b", 0) for p in packets if p.get("dir") == "<"]
    iat = [p.get("ipt", 0) for p in packets[1:]]  # first ipt is 0
    d = {}
    d.update(_stats(fwd, "fwd_pktsize"))
    d.update(_stats(bwd, "bwd_pktsize"))
    d.update(_stats(iat, "iat_ms"))
    return d


def _read_joy(path: Path | str) -> tuple[list, list]:
    """Return (core_rows, derived_rows) from a gzipped Joy NDJSON file."""
    core, derived = [], []
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "version" in obj or "sa" not in obj:  # config/header line
                continue
            core.append(obj)
            derived.append(_derive(obj.get("packets", []) or []))
    return core, derived


def to_canonical(core: list, derived: list, *, dataset: str, capture: str) -> pd.DataFrame:
    n = len(core)
    j = pd.DataFrame(core)
    out = pd.DataFrame(index=range(n))
    out["src_ip"] = j.get("sa", pd.Series([pd.NA] * n)).astype("string")
    out["dst_ip"] = j.get("da", pd.Series([pd.NA] * n)).astype("string")
    out["src_port"] = pd.to_numeric(j.get("sp"), errors="coerce")
    out["dst_port"] = pd.to_numeric(j.get("dp"), errors="coerce")
    out["proto"] = j.get("pr").map(C.proto_to_number) if "pr" in j else pd.NA
    out["t_start"] = pd.to_numeric(j.get("time_start"), errors="coerce")
    _t_end = pd.to_numeric(j.get("time_end"), errors="coerce")
    # Joy occasionally emits time_end < time_start; clip so t_end >= t_start.
    out["duration"] = (_t_end - out["t_start"]).clip(lower=0)
    out["t_end"] = out["t_start"] + out["duration"]
    out["pkts_fwd"] = pd.to_numeric(j.get("num_pkts_out"), errors="coerce")
    out["pkts_bwd"] = pd.to_numeric(j.get("num_pkts_in"), errors="coerce")
    out["bytes_fwd"] = pd.to_numeric(j.get("bytes_out"), errors="coerce")
    out["bytes_bwd"] = pd.to_numeric(j.get("bytes_in"), errors="coerce")
    # Joy has no TCP flag counts -> <NA>
    out["tool"] = TOOL
    out["dataset"] = dataset
    out["capture"] = capture
    out["flow_id"] = pd.Series(range(n)).astype("string")

    # native: Joy's own scalar fields (drop the big packets array) + our derived
    native = j.drop(columns=[c for c in ("packets", "byte_dist") if c in j.columns])
    native = C.prefix_native(native)
    der = pd.DataFrame(derived).rename(columns=lambda c: f"tool_derived_{c}")
    out = pd.concat([out.reset_index(drop=True), native.reset_index(drop=True),
                     der.reset_index(drop=True)], axis=1)
    # drop degenerate zero-packet records (rare Joy control/metadata rows)
    tot = out["pkts_fwd"].fillna(0) + out["pkts_bwd"].fillna(0)
    out = out[tot > 0].reset_index(drop=True)
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
        raise RuntimeError(f"{TOOL} failed (rc={proc.returncode}):\n{proc.stderr[-2000:]}")
    gzs = sorted(out_dir.glob("*.json.gz")) or sorted(out_dir.glob("*.gz"))
    if not gzs:
        raise RuntimeError(f"{TOOL} produced no json.gz in {out_dir}")
    core, derived = [], []
    for gz in gzs:
        c, d = _read_joy(gz)
        core += c
        derived += d
    df = to_canonical(core, derived, dataset=dataset, capture=capture)
    meta = RunMeta(
        tool=TOOL, tool_version=image, dataset=dataset, capture=capture,
        pcap_path=str(pcap), pcap_fingerprint=pcap_fingerprint(pcap),
        config={"image": image, "bidir": 1, "num_pkts": 200,
                "derived": "fwd/bwd pktsize + iat stats"}, n_flows=len(df),
    )
    write_outputs(df, out_path, meta)
    return out_path


def _cli(argv=None):
    ap = argparse.ArgumentParser(description="Joy -> canonical parquet (Docker)")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--capture", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    print("wrote", extract(args.pcap, dataset=args.dataset, capture=args.capture, out_path=args.out))


if __name__ == "__main__":
    _cli()
