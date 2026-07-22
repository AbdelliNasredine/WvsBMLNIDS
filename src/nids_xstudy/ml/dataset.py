"""Load labeled canonical flows and build feature matrices + splits."""
from __future__ import annotations

import re

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from .. import config as cfg

# harmonized core features available across all tools (from the canonical schema)
COMMON_CORE = ["duration", "pkts_fwd", "pkts_bwd", "bytes_fwd", "bytes_bwd"]

# native columns that are identifiers / shortcuts, not statistical features
_ID_PAT = re.compile(
    r"(^|_)(ip|ipv4|ipv6|addr|mac|oui|host|hostname|port|sport|dport|"
    r"time|first|last|start|end|stime|ltime|timestamp|id|flowind|flow_id|"
    r"uid|vlan|tunnel|label|src|dst|saddr|daddr)($|_)", re.I)

TRAIN_DAYS = ("Monday", "Tuesday", "Wednesday")
TEST_DAYS = ("Thursday", "Friday")


def temporal_caps(dataset: str | None = None) -> tuple[list[str], list[str]]:
    """(train_captures, test_captures) for the temporal split. Reads the
    ``split:`` block of configs/datasets/<dataset>.yaml when present; falls back
    to the CICIDS Mon-Wed / Thu-Fri constants (keeps existing results stable)."""
    if dataset is not None:
        split = cfg.dataset_spec(dataset).get("split") or {}
        if split.get("train") and split.get("test"):
            return list(split["train"]), list(split["test"])
    return list(TRAIN_DAYS), list(TEST_DAYS)


def load_tool(tool: str, dataset: str = "cicids2017", captures=None) -> pd.DataFrame:
    caps = captures or cfg.captures(dataset)
    frames = []
    for cap in caps:
        p = cfg.labeled_dir(dataset, tool) / f"{cap}.parquet"
        if p.exists():
            df = pd.read_parquet(p)
            df["_capture"] = cap
            frames.append(df)
    if not frames:
        raise FileNotFoundError(f"no labeled parquet for tool {tool!r}")
    return pd.concat(frames, ignore_index=True)


def common_features(df: pd.DataFrame, include_port: bool = False) -> pd.DataFrame:
    X = pd.DataFrame(index=df.index)
    for c in COMMON_CORE:
        X[c] = pd.to_numeric(df[c], errors="coerce")
    X["tot_pkts"] = X["pkts_fwd"].fillna(0) + X["pkts_bwd"].fillna(0)
    X["tot_bytes"] = X["bytes_fwd"].fillna(0) + X["bytes_bwd"].fillna(0)
    proto = pd.to_numeric(df["proto"], errors="coerce")
    X["is_tcp"] = (proto == 6).astype("float64")
    X["is_udp"] = (proto == 17).astype("float64")
    if include_port:
        X["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
    return X


def native_features(df: pd.DataFrame, min_numeric_frac: float = 0.5) -> pd.DataFrame:
    keep = []
    for c in df.columns:
        if not c.startswith("tool_"):
            continue
        name = c[len("tool_"):]
        if _ID_PAT.search(name):
            continue
        s = pd.to_numeric(df[c], errors="coerce")
        if s.notna().mean() < min_numeric_frac:
            continue
        keep.append(c)
    if not keep:
        # fall back to common core if a tool exposes no usable native features
        return common_features(df)
    X = df[keep].apply(pd.to_numeric, errors="coerce")
    X = X.loc[:, X.nunique(dropna=True) > 1]  # drop constant columns
    return X


def feature_matrix(df: pd.DataFrame, regime: str, include_port: bool = False):
    if regime == "common":
        X = common_features(df, include_port=include_port)
    elif regime == "native":
        X = native_features(df)
    else:
        raise ValueError(f"unknown regime {regime!r}")
    return X.astype("float64"), list(X.columns)


def labels(df: pd.DataFrame, task: str = "binary"):
    if task == "binary":
        return (df["binary_label"].astype("string") == "ATTACK").astype(int).to_numpy()
    return df["label"].astype("string").fillna("BENIGN").to_numpy()


def split_mask(df, y, kind: str, seed: int, test_size: float = 0.3, dataset: str | None = None):
    """Return boolean (train_mask, test_mask).

    ``dataset``: when the split is ``temporal``, resolves the train/test capture
    partition from that dataset's config (defaults to the CICIDS day tuples)."""
    n = len(df)
    if kind == "temporal":
        train_caps, test_caps = temporal_caps(dataset)
        cap = df["_capture"].to_numpy()
        tr = np.isin(cap, train_caps)
        te = np.isin(cap, test_caps)
        return tr, te
    if kind == "stratified":
        y = np.asarray(y)
        vals, counts = np.unique(y, return_counts=True)
        rare = set(vals[counts < 2].tolist())  # classes too small to stratify
        tr = np.zeros(n, bool); te = np.zeros(n, bool)
        rare_mask = np.isin(y, list(rare)) if rare else np.zeros(n, bool)
        tr[rare_mask] = True  # singleton classes -> train (can't be in both)
        rest = np.where(~rare_mask)[0]
        tr_idx, te_idx = train_test_split(rest, test_size=test_size, random_state=seed,
                                          stratify=y[rest])
        tr[tr_idx] = True; te[te_idx] = True
        return tr, te
    raise ValueError(f"unknown split {kind!r}")
