"""Hybrid Reconnaissance projection for DAPT2020.

DAPT2020's Reconnaissance stage cannot be separated from benign by time+IP+port
(the scanner/C&C source IPs also produce large volumes of benign traffic to the
same victim and ports in the same windows). Per the approved hybrid labeling
decision, this ONE stage is taken from DAPT's own per-flow label, projected onto
each extractor's flows by 5-tuple + nearest-time so that the rest of the labels
stay independent and the recon flows are still consistent across extractors.

``recon_flows.parquet`` (produced by scripts/derive_dapt20_rules.py) holds every
CSV-labeled Reconnaissance flow as {src_ip, dst_ip, src_port, dst_port, proto,
t_start (UTC epoch)}. :func:`apply_recon` relabels a canonical/labeled frame's
currently-BENIGN flows that match a recon reference flow (direction-agnostic IP
and port pair, same proto, |t_start - ref| <= tol) to ``Reconnaissance``.
"""
from __future__ import annotations

import bisect
from pathlib import Path

import numpy as np
import pandas as pd

from .engine import ATTACK, BENIGN

RECON_LABEL = "Reconnaissance"


def _key(src_ip, dst_ip, src_port, dst_port, proto):
    # ordered 5-tuple: recon is attacker->victim and tools orient by first packet,
    # so an ordered key avoids matching benign return/collision flows.
    return (str(src_ip), int(src_port), str(dst_ip), int(dst_port), int(proto))


def load_recon_ref(path: Path | str, capture: str | None = None) -> dict:
    """Index recon reference flows by ordered 5-tuple -> sorted t_starts.

    ``capture``: restrict to recon flows collected from that capture (avoids
    projecting Tuesday-public recon onto a duplicate flow in another capture)."""
    df = pd.read_parquet(path)
    if capture is not None and "_capture" in df.columns:
        df = df[df["_capture"] == capture]
    index: dict = {}
    for r in df.itertuples(index=False):
        try:
            k = _key(r.src_ip, r.dst_ip, r.src_port, r.dst_port, r.proto)
        except (ValueError, TypeError):
            continue
        index.setdefault(k, []).append(float(r.t_start))
    for k in index:
        index[k].sort()
    return index


def apply_recon(df: pd.DataFrame, ref_index: dict, tol_s: float = 2.0) -> pd.DataFrame:
    """Relabel BENIGN flows matching a recon reference flow to Reconnaissance.

    Requires df to already carry ``label``/``binary_label`` (from label_flows) and
    the canonical 5-tuple + ``t_start``. Only BENIGN flows are considered, so
    rule-labeled attack stages are never overwritten. Returns df (modified copy).
    """
    if not ref_index or "label" not in df.columns:
        return df
    df = df.copy()
    label = df["label"].astype("object").to_numpy()
    binary = df["binary_label"].astype("object").to_numpy()
    conf = (df["label_confidence"].astype("object").to_numpy()
            if "label_confidence" in df.columns else np.array(["benign"] * len(df), dtype=object))

    src_ip = df["src_ip"].to_numpy(); dst_ip = df["dst_ip"].to_numpy()
    src_port = pd.to_numeric(df["src_port"], errors="coerce").to_numpy()
    dst_port = pd.to_numeric(df["dst_port"], errors="coerce").to_numpy()
    proto = pd.to_numeric(df["proto"], errors="coerce").to_numpy()
    t_start = pd.to_numeric(df["t_start"], errors="coerce").to_numpy()

    n_hit = 0
    for i in range(len(df)):
        if binary[i] == ATTACK:
            continue  # never overwrite a rule-assigned attack stage
        sp, dp, pr, ts = src_port[i], dst_port[i], proto[i], t_start[i]
        if not (np.isfinite(sp) and np.isfinite(dp) and np.isfinite(pr) and np.isfinite(ts)):
            continue
        starts = ref_index.get(_key(src_ip[i], dst_ip[i], sp, dp, pr))
        if not starts:
            continue
        j = bisect.bisect_left(starts, ts)
        near = min(
            (abs(starts[k] - ts) for k in (j - 1, j) if 0 <= k < len(starts)),
            default=tol_s + 1,
        )
        if near <= tol_s:
            label[i] = RECON_LABEL
            binary[i] = ATTACK
            conf[i] = "projected"
            n_hit += 1

    df["label"] = pd.array(label, dtype="string")
    df["binary_label"] = pd.array(binary, dtype="string")
    df["label_confidence"] = pd.array(conf, dtype="string")
    df.attrs["recon_projected"] = n_hit
    return df


def recon_ref_path(dataset: str, cfg) -> Path | None:
    """Return the recon reference path for a dataset if it exists, else None."""
    p = cfg.labels_dir(dataset) / "recon_flows.parquet"
    return p if p.exists() else None
