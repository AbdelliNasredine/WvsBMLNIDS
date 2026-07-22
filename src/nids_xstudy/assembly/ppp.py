"""Dockerized PcapPlusPlus flow assembler -> same (meta, images) contract as the
reference :func:`nids_xstudy.assembly.assembler.assemble`.

The heavy lifting runs in the ``nids-xstudy/ppp-assembler`` image (C++ /
PcapPlusPlus), which is a byte-for-byte reimplementation of the scapy reference
assembler but fast enough for the 10-13 GB CIC-IDS2017 pcapng captures. This
wrapper runs the container (reusing ``extraction._docker.run`` for the standard
/pcaps + /out mounts), reads the three output files and returns:

    (meta: pandas.DataFrame, images: np.ndarray[uint8, (n_flows, max_pkts, max_bytes)])

with the *same columns and dtypes* as the Python ``assemble()`` -- including
``dirs``/``times``/``sizes`` parsed back into Python lists.

Temp/output files live under ``config.data_root()`` (the E: drive), never C:,
because assembled artifacts are large.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

from .. import config as cfg
from ..extraction import _docker
from .assembler import ASSEMBLY_DEFAULTS, AssemblyConfig, _META_COLS

IMAGE = "nids-xstudy/ppp-assembler:1"

_SEQ_COLS = ["dirs", "times", "sizes"]


def _parse_int_list(cell: str) -> list[int]:
    if not isinstance(cell, str) or not cell.strip():
        return []
    return [int(x) for x in cell.split()]


def _parse_float_list(cell: str) -> list[float]:
    if not isinstance(cell, str) or not cell.strip():
        return []
    return [float(x) for x in cell.split()]


def _read_outputs(prefix: Path, cfg_obj: AssemblyConfig) -> tuple[pd.DataFrame, np.ndarray]:
    # Filenames are `<prefix>.<ext>` by string concatenation (matching the C++
    # tool's out_prefix + ".ext"); with_suffix would mangle a prefix with a dot.
    p = str(prefix)
    info = json.loads(Path(p + ".info.json").read_text())
    n_flows = int(info["n_flows"])
    max_pkts = int(info["max_pkts"])
    max_bytes = int(info["max_bytes"])

    meta_csv = Path(p + ".meta.csv")
    df = pd.read_csv(
        meta_csv,
        converters={"dirs": _parse_int_list,
                    "times": _parse_float_list,
                    "sizes": _parse_int_list},
    )
    # Match the reference dtypes exactly (ints for counts/ports, float for times).
    int_cols = ["flow_id", "src_port", "dst_port", "proto", "n_pkts", "n_bytes",
                "pkts_fwd", "pkts_bwd", "bytes_fwd", "bytes_bwd", "seq_len"]
    for c in int_cols:
        df[c] = df[c].astype("int64")
    for c in ("t_start", "t_end", "duration"):
        df[c] = df[c].astype("float64")
    df["src_ip"] = df["src_ip"].astype(object)
    df["dst_ip"] = df["dst_ip"].astype(object)
    df = df[_META_COLS + _SEQ_COLS]

    images_bin = Path(p + ".images.bin")
    raw = np.fromfile(images_bin, dtype=np.uint8)
    expected = n_flows * max_pkts * max_bytes
    if raw.size != expected:
        raise RuntimeError(
            f"images.bin size {raw.size} != n_flows*max_pkts*max_bytes {expected}")
    images = raw.reshape(n_flows, max_pkts, max_bytes)
    return df, images


def assemble_ppp(
    pcap_path: Path | str,
    cfg_obj: AssemblyConfig = ASSEMBLY_DEFAULTS,
    *,
    image: str = IMAGE,
    keep_tmp: bool = False,
    timeout: int | None = None,
) -> tuple[pd.DataFrame, np.ndarray]:
    """Assemble ``pcap_path`` with the Dockerized PcapPlusPlus tool.

    Returns ``(meta, images)`` identical in shape/columns to
    :func:`nids_xstudy.assembly.assembler.assemble`.
    """
    pcap = Path(pcap_path)
    if not pcap.exists():
        raise FileNotFoundError(pcap)

    # Container out-dir lives under data_root() (E:), NOT C:.
    tmp_root = cfg.data_root() / "tmp_ppp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    out_dir = Path(tempfile.mkdtemp(prefix=f"{pcap.stem}_", dir=str(tmp_root)))

    try:
        prefix_name = pcap.stem  # <out_dir>/<stem>.{meta.csv,images.bin,info.json}
        container_cmd = [
            f"/pcaps/{pcap.name}",
            f"/out/{prefix_name}",
            "--idle", repr(float(cfg_obj.idle_timeout)),
            "--active", repr(float(cfg_obj.active_timeout)),
            "--max-pkts", str(int(cfg_obj.max_pkts)),
            "--max-bytes", str(int(cfg_obj.max_bytes)),
        ]
        proc = _docker.run(
            image, container_cmd,
            pcap=pcap, out_dir=out_dir, workdir="/out", timeout=timeout,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"ppp-assembler failed (rc={proc.returncode}):\n"
                f"STDERR:\n{proc.stderr[-4000:]}\nSTDOUT:\n{proc.stdout[-1000:]}")

        prefix = out_dir / prefix_name
        return _read_outputs(prefix, cfg_obj)
    finally:
        if not keep_tmp:
            shutil.rmtree(out_dir, ignore_errors=True)
