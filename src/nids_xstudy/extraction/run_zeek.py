"""Zeek extraction runner: PCAP -> conn.log (+ flag counts) -> canonical parquet.

Runs the Dockerized Zeek image (env/docker/zeek) which emits conn.log augmented
with per-direction TCP flag counts (flowfeatures.zeek). Zeek's originator = our
``fwd`` direction.

Byte semantics: we map Zeek ``orig_ip_bytes``/``resp_ip_bytes`` (IP-layer bytes)
to canonical bytes, comparable to NFStream accounting_mode=1. Zeek ``orig_bytes``
(payload only) is retained as a tool_ column.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from .. import canonical as C
from .. import config as cfg
from . import _docker
from .base import RunMeta, pcap_fingerprint, write_outputs

TOOL = "zeek"
IMAGE = "nids-xstudy/zeek:6.0.0"

# Zeek '-' / '(empty)' sentinels
_UNSET = {"-", "(empty)"}


def parse_zeek_log(path: Path | str) -> pd.DataFrame:
    """Parse a Zeek TSV log (conn.log) into a DataFrame using its #fields header."""
    path = Path(path)
    sep = "\t"
    fields: list[str] | None = None
    rows: list[list[str]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#"):
                if line.startswith("#separator"):
                    token = line.split(" ", 1)[1].strip()
                    sep = token.encode().decode("unicode_escape") if "\\x" in token else token
                elif line.startswith("#fields"):
                    fields = line.split(sep)[1:]
                continue
            if not line:
                continue
            rows.append(line.split(sep))
    if fields is None:
        raise ValueError(f"no #fields header in {path}")
    df = pd.DataFrame(rows, columns=fields)
    return df.replace(list(_UNSET), pd.NA)


def _num(s: pd.Series) -> pd.Series:
    return pd.to_numeric(s, errors="coerce")


def to_canonical(z: pd.DataFrame, *, dataset: str, capture: str) -> pd.DataFrame:
    n = len(z)
    out = pd.DataFrame(index=range(n))
    out["src_ip"] = z["id.orig_h"].astype("string")
    out["dst_ip"] = z["id.resp_h"].astype("string")
    out["src_port"] = _num(z["id.orig_p"])
    out["dst_port"] = _num(z["id.resp_p"])
    out["proto"] = z["proto"].map(C.proto_to_number)

    ts = _num(z["ts"])
    dur = _num(z["duration"]).fillna(0.0)
    out["t_start"] = ts
    out["t_end"] = ts + dur
    out["duration"] = dur

    out["pkts_fwd"] = _num(z["orig_pkts"])
    out["pkts_bwd"] = _num(z["resp_pkts"])
    out["bytes_fwd"] = _num(z["orig_ip_bytes"])
    out["bytes_bwd"] = _num(z["resp_ip_bytes"])

    flag_map = {"syn": "syn", "fin": "fin", "rst": "rst", "psh": "psh", "ack": "ack", "urg": "urg"}
    for canon, z_stem in flag_map.items():
        s_col, r_col = f"s_{z_stem}", f"r_{z_stem}"
        out[f"{canon}_fwd"] = _num(z[s_col]) if s_col in z else pd.NA
        out[f"{canon}_bwd"] = _num(z[r_col]) if r_col in z else pd.NA
    # ece/cwr not exposed by Zeek flags string -> remain <NA>
    out["ece_fwd"] = pd.NA; out["ece_bwd"] = pd.NA
    out["cwr_fwd"] = pd.NA; out["cwr_bwd"] = pd.NA

    out["tool"] = TOOL
    out["dataset"] = dataset
    out["capture"] = capture
    out["flow_id"] = z["uid"].astype("string") if "uid" in z else pd.Series(range(n)).astype("string")

    native = C.prefix_native(z)
    out = pd.concat([out.reset_index(drop=True), native.reset_index(drop=True)], axis=1)
    return C.coerce_schema(out)


def extract(
    pcap: Path | str,
    *,
    dataset: str,
    capture: str,
    image: str = IMAGE,
    out_path: Path | str | None = None,
    keep_logs: bool = True,
) -> Path:
    pcap = Path(pcap)
    if out_path is None:
        out_path = cfg.canonical_dir(dataset, TOOL) / f"{capture}.parquet"
    out_path = Path(out_path)
    log_dir = cfg.extracted_dir(dataset, TOOL) / capture
    log_dir.mkdir(parents=True, exist_ok=True)

    # zeek writes conn.log into the working dir (/out mounted to log_dir)
    proc = _docker.run(
        image,
        ["-C", "-r", f"/pcaps/{pcap.name}",
         "/opt/zeek/share/zeek/site/flowfeatures.zeek"],
        pcap=pcap, out_dir=log_dir, workdir="/out",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"zeek failed (rc={proc.returncode}):\n{proc.stderr[-2000:]}")

    conn_log = log_dir / "conn.log"
    if not conn_log.exists():
        raise RuntimeError(f"zeek produced no conn.log in {log_dir}")

    z = parse_zeek_log(conn_log)
    df = to_canonical(z, dataset=dataset, capture=capture)

    meta = RunMeta(
        tool=TOOL, tool_version=image, dataset=dataset, capture=capture,
        pcap_path=str(pcap), pcap_fingerprint=pcap_fingerprint(pcap),
        config={"image": image, "checksum_ignore": True,
                "script": "flowfeatures.zeek", "bytes": "ip_bytes"},
        n_flows=len(df),
    )
    write_outputs(df, out_path, meta)
    if not keep_logs:
        for p in log_dir.glob("*.log"):
            p.unlink()
    return out_path


def _cli(argv=None):
    ap = argparse.ArgumentParser(description="Zeek -> canonical parquet (Docker)")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--capture", required=True)
    ap.add_argument("--image", default=IMAGE)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    print("wrote", extract(args.pcap, dataset=args.dataset, capture=args.capture,
                           image=args.image, out_path=args.out))


if __name__ == "__main__":
    _cli()
