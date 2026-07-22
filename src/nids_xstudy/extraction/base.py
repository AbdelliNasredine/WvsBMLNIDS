"""Shared utilities for extraction runners: provenance + sidecar metadata.

Every result on disk must be traceable to the exact inputs that produced it
(plan section 3: "No un-versioned results"). Runners call :func:`build_meta`
and :func:`write_outputs` so that each canonical parquet gets a sibling
``.meta.json`` embedding tool version, config, config hash, git commit and a
PCAP fingerprint.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import pandas as pd

from .. import __version__
from .. import canonical as C


def git_commit() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parents[3],
            capture_output=True, text=True, timeout=10,
        )
        return out.stdout.strip() or None if out.returncode == 0 else None
    except Exception:
        return None


def pcap_fingerprint(path: Path | str) -> dict[str, Any]:
    """Cheap, stable fingerprint of a (possibly multi-GB) PCAP.

    Hashing 10 GB per run is wasteful; we fingerprint by name + size + a hash of
    the first and last 4 MiB, which is sufficient to detect a changed/replaced
    capture without a full read.
    """
    path = Path(path)
    st = path.stat()
    h = hashlib.sha256()
    chunk = 4 * 1024 * 1024
    with open(path, "rb") as fh:
        head = fh.read(chunk)
        h.update(head)
        if st.st_size > chunk:
            fh.seek(max(0, st.st_size - chunk))
            h.update(fh.read(chunk))
    return {
        "name": path.name,
        "size_bytes": st.st_size,
        "edge_sha256": h.hexdigest(),
    }


def config_hash(cfg: dict) -> str:
    blob = json.dumps(cfg, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


@dataclass
class RunMeta:
    tool: str
    tool_version: str
    dataset: str
    capture: str
    pcap_path: str
    pcap_fingerprint: dict
    config: dict
    n_flows: int
    pkg_version: str = __version__
    git_commit: str | None = field(default_factory=git_commit)
    config_hash: str = ""

    def __post_init__(self):
        if not self.config_hash:
            self.config_hash = config_hash(self.config)


def write_outputs(df: pd.DataFrame, canonical_path: Path | str, meta: RunMeta) -> Path:
    """Validate + write the canonical parquet and its sidecar meta json."""
    canonical_path = Path(canonical_path)
    canonical_path.parent.mkdir(parents=True, exist_ok=True)
    C.write(df, canonical_path, validate_first=True)
    meta_path = canonical_path.with_suffix(".meta.json")
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(asdict(meta), fh, indent=2, default=str)
    return canonical_path
