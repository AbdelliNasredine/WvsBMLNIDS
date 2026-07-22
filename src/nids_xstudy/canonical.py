"""Canonical flow schema — the single data contract shared by every extractor.

Each per-tool runner emits one parquet file conforming to this schema: one row
per flow, with a fixed set of tool-agnostic *core* columns plus arbitrarily many
tool-native columns (prefixed ``tool_``). Everything downstream (labeling, flow
alignment, harmonization, ML) reads only the canonical schema, which is what
makes the extractor the *only* thing that varies between experimental conditions.

Conventions
-----------
* **Directionality**: ``fwd`` = the direction of the flow initiator (the endpoint
  that sent the first packet). ``src_ip/src_port`` identify that initiator;
  ``dst_ip/dst_port`` the responder. Every runner MUST adopt this convention so
  forward/backward counts are comparable across tools.
* **Time**: ``t_start``/``t_end`` are UTC epoch seconds (float64). Runners are
  responsible for normalizing tool-native timestamps (which may be local time,
  microseconds, etc.) to UTC epoch seconds at parse time. ``duration`` is
  ``t_end - t_start`` in seconds.
* **proto**: IANA protocol number (int16). 6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6.
* **Flag counts**: number of packets in that direction whose TCP header had the
  flag set. Left as <NA> (nullable Int64) for non-TCP flows or tools that do not
  report a given flag.
"""
from __future__ import annotations

from typing import Any, Iterable

import pandas as pd

# ---------------------------------------------------------------------------
# Column definitions
# ---------------------------------------------------------------------------

FLOW_KEY = ["src_ip", "src_port", "dst_ip", "dst_port", "proto"]

FLAG_NAMES = ["syn", "fin", "rst", "psh", "ack", "urg", "ece", "cwr"]
FLAG_COLUMNS = [f"{flag}_{d}" for d in ("fwd", "bwd") for flag in FLAG_NAMES]

# Provenance columns identify which run produced the row.
PROVENANCE = ["tool", "dataset", "capture", "flow_id"]

CORE_COLUMNS = (
    FLOW_KEY
    + ["t_start", "t_end", "duration",
       "pkts_fwd", "pkts_bwd", "bytes_fwd", "bytes_bwd"]
    + FLAG_COLUMNS
    + PROVENANCE
)

# pandas dtypes for the core columns. Nullable integer types (Int*) let us
# represent "tool did not report this" as <NA> without collapsing to float.
_STR = "string"
_F64 = "float64"
_I64 = "Int64"
_I32 = "Int32"
_I16 = "Int16"

CORE_DTYPES: dict[str, str] = {
    "src_ip": _STR, "dst_ip": _STR,
    "src_port": _I32, "dst_port": _I32, "proto": _I16,
    "t_start": _F64, "t_end": _F64, "duration": _F64,
    "pkts_fwd": _I64, "pkts_bwd": _I64, "bytes_fwd": _I64, "bytes_bwd": _I64,
    **{c: _I64 for c in FLAG_COLUMNS},
    "tool": _STR, "dataset": _STR, "capture": _STR, "flow_id": _STR,
}

TOOL_PREFIX = "tool_"


# ---------------------------------------------------------------------------
# Protocol helpers
# ---------------------------------------------------------------------------

_PROTO_NAME_TO_NUM = {
    "hopopt": 0, "icmp": 1, "igmp": 2, "tcp": 6, "udp": 17, "gre": 47,
    "esp": 50, "ah": 51, "icmpv6": 58, "ipv6-icmp": 58, "ospf": 89, "sctp": 132,
}
_PROTO_NUM_TO_NAME = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6", 2: "igmp"}


def proto_to_number(proto: Any) -> int | None:
    """Coerce a tool's protocol representation to an IANA protocol number.

    Handles Python/NumPy ints and floats (6.0 -> 6; a float is common when a
    tool's JSON column is float-typed due to NaN in other rows), digit strings
    ("6"), and protocol names ("tcp").
    """
    if proto is None:
        return None
    if isinstance(proto, bool):
        return None
    # numeric (int/float/numpy) — but not a bare string
    if not isinstance(proto, str):
        try:
            if pd.isna(proto):
                return None
            return int(float(proto))
        except (TypeError, ValueError):
            pass
    s = str(proto).strip().lower()
    if not s or s == "nan":
        return None
    if s.replace(".", "", 1).isdigit():
        return int(float(s))
    return _PROTO_NAME_TO_NUM.get(s)


def proto_name(number: int | None) -> str:
    if number is None:
        return "unknown"
    return _PROTO_NUM_TO_NAME.get(int(number), str(number))


# ---------------------------------------------------------------------------
# Flow-key helpers
# ---------------------------------------------------------------------------

def directed_key(row: pd.Series | dict) -> tuple:
    """Initiator-ordered 5-tuple (as stored)."""
    return (row["src_ip"], row["src_port"], row["dst_ip"], row["dst_port"], row["proto"])


def bidirectional_key(row: pd.Series | dict) -> tuple:
    """Direction-independent 5-tuple for cross-tool matching.

    Orders the two (ip, port) endpoints canonically so that a flow and its
    reverse map to the same key regardless of which endpoint a tool calls the
    source. Used by Phase-2 flow alignment.
    """
    a = (str(row["src_ip"]), int(row["src_port"]) if pd.notna(row["src_port"]) else -1)
    b = (str(row["dst_ip"]), int(row["dst_port"]) if pd.notna(row["dst_port"]) else -1)
    lo, hi = sorted((a, b))
    proto = int(row["proto"]) if pd.notna(row["proto"]) else -1
    return (lo[0], lo[1], hi[0], hi[1], proto)


# ---------------------------------------------------------------------------
# Assembly / validation / IO
# ---------------------------------------------------------------------------

def empty_frame() -> pd.DataFrame:
    """An empty canonical DataFrame with correct columns and dtypes."""
    df = pd.DataFrame({c: pd.Series([], dtype=CORE_DTYPES[c]) for c in CORE_COLUMNS})
    return df


def coerce_schema(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure every core column exists with the canonical dtype.

    Missing core columns are added as all-<NA>. Tool-native columns (``tool_*``)
    are left untouched. Column order = core columns first, then native columns.
    """
    df = df.copy()
    for col in CORE_COLUMNS:
        if col not in df.columns:
            df[col] = pd.Series([pd.NA] * len(df), dtype=CORE_DTYPES[col])
        else:
            df[col] = df[col].astype(CORE_DTYPES[col])
    native = [c for c in df.columns if c.startswith(TOOL_PREFIX)]
    other = [c for c in df.columns if c not in CORE_COLUMNS and c not in native]
    if other:
        raise ValueError(
            f"Non-canonical, non-tool_ columns present: {other}. "
            f"Prefix tool-native columns with {TOOL_PREFIX!r}."
        )
    # Mixed-type native columns (e.g. a port column that is int for some flows
    # and a service string for others) break the parquet writer. Stringify any
    # object-dtype native column so the wide native vector always serializes.
    for c in native:
        if df[c].dtype == object:
            df[c] = df[c].astype("string")
    return df[CORE_COLUMNS + native]


def validate(df: pd.DataFrame, *, strict: bool = True) -> list[str]:
    """Return a list of schema/consistency problems (empty == valid).

    With ``strict=True`` (default) raises ValueError if any problem is found.
    """
    problems: list[str] = []
    for col in CORE_COLUMNS:
        if col not in df.columns:
            problems.append(f"missing core column: {col}")
    if problems:  # can't check values without columns
        if strict:
            raise ValueError("; ".join(problems))
        return problems

    if len(df):
        if (df["t_end"] < df["t_start"]).any():
            problems.append("t_end < t_start for some rows")
        dur = df["t_end"] - df["t_start"]
        # allow tiny float noise
        if ((df["duration"] - dur).abs() > 1e-3).any():
            problems.append("duration != t_end - t_start for some rows")
        for col in ["pkts_fwd", "pkts_bwd", "bytes_fwd", "bytes_bwd"]:
            if (df[col].dropna() < 0).any():
                problems.append(f"negative values in {col}")
        if (df[["pkts_fwd", "pkts_bwd"]].fillna(0).sum(axis=1) == 0).any():
            problems.append("flows with zero total packets present")
        # a flow must have an initiator IP
        if df["src_ip"].isna().any() or df["dst_ip"].isna().any():
            problems.append("null src_ip/dst_ip present")

    if strict and problems:
        raise ValueError("canonical validation failed: " + "; ".join(problems))
    return problems


def write(df: pd.DataFrame, path, *, validate_first: bool = True) -> None:
    df = coerce_schema(df)
    if validate_first:
        validate(df, strict=True)
    df.to_parquet(path, engine="pyarrow", index=False)


def read(path) -> pd.DataFrame:
    df = pd.read_parquet(path, engine="pyarrow")
    return coerce_schema(df)


def prefix_native(native: dict[str, Any] | pd.DataFrame) -> dict[str, Any] | pd.DataFrame:
    """Prefix a mapping/DataFrame of tool-native feature columns with ``tool_``.

    Columns already prefixed are left as-is.
    """
    def _key(k: str) -> str:
        return k if k.startswith(TOOL_PREFIX) else f"{TOOL_PREFIX}{k}"

    if isinstance(native, pd.DataFrame):
        return native.rename(columns={c: _key(c) for c in native.columns})
    return {_key(k): v for k, v in native.items()}
