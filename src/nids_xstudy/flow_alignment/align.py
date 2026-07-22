"""Match flows between two tools and classify segmentation agreement.

Approach (efficient, vectorized):
1. Give every flow an order-independent 5-tuple key (so tools that orient a flow
   differently still collide).
2. For flows sharing a key, form all (a, b) pairs and keep the temporally
   overlapping ones (interval overlap on [t_start, t_end]).
3. Classify each flow of A (relative to B) from the overlap multiplicities:
   * unmatched : overlaps 0 B flows
   * 1:1       : overlaps exactly 1 B flow, which overlaps exactly 1 A flow
   * split     : overlaps >1 B flows  (A coarser — B split it)
   * merge     : overlaps 1 B flow that overlaps >1 A flows (A finer)

The result is per-A-flow categories (+ the A label) and the list of 1:1 pairs
(for feature-value divergence).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

CATEGORIES = ["1:1", "split", "merge", "unmatched"]


def bidir_key_series(df: pd.DataFrame) -> pd.Series:
    """Vectorized order-independent 5-tuple key ('lo|hi|proto')."""
    sp = df["src_port"].astype("Float64").fillna(-1).astype("int64").astype("string")
    dp = df["dst_port"].astype("Float64").fillna(-1).astype("int64").astype("string")
    proto = df["proto"].astype("Float64").fillna(-1).astype("int64").astype("string")
    a = df["src_ip"].astype("string").fillna("?") + ":" + sp
    b = df["dst_ip"].astype("string").fillna("?") + ":" + dp
    ends = pd.DataFrame({"a": a, "b": b})
    lo = ends.min(axis=1)
    hi = ends.max(axis=1)
    return (lo + "|" + hi + "|" + proto).astype("string")


def match_pair(dfA: pd.DataFrame, dfB: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (a_cat, pairs_1to1).

    a_cat: DataFrame indexed by A row with columns [label, category, nB].
    pairs_1to1: DataFrame [ia, ib] of clean 1:1 matches (for feature compare).
    """
    A = pd.DataFrame({
        "ia": np.arange(len(dfA)),
        "key": bidir_key_series(dfA).to_numpy(),
        "ts": dfA["t_start"].to_numpy(dtype="float64"),
        "te": dfA["t_end"].to_numpy(dtype="float64"),
        "label": dfA["label"].astype("string").to_numpy(),
    })
    B = pd.DataFrame({
        "ib": np.arange(len(dfB)),
        "key": bidir_key_series(dfB).to_numpy(),
        "ts": dfB["t_start"].to_numpy(dtype="float64"),
        "te": dfB["t_end"].to_numpy(dtype="float64"),
    })

    m = A[["ia", "key", "ts", "te"]].merge(B, on="key", suffixes=("_a", "_b"))
    overlap = (m["ts_a"] <= m["te_b"]) & (m["ts_b"] <= m["te_a"])
    pairs = m.loc[overlap, ["ia", "ib"]].reset_index(drop=True)

    a_nB = pairs.groupby("ia").size()          # #B each A overlaps
    b_nA = pairs.groupby("ib").size()          # #A each B overlaps

    a_cat = pd.DataFrame({"label": A["label"], "nB": A["ia"].map(a_nB).fillna(0).astype("int64")})

    # for A flows with exactly one B match, is that B a singleton on its side?
    singles = pairs[pairs["ia"].map(a_nB).eq(1)].copy()
    singles["b_nA"] = singles["ib"].map(b_nA)
    matched_b_nA = singles.set_index("ia")["b_nA"]

    cat = np.full(len(A), "unmatched", dtype=object)
    nB = a_cat["nB"].to_numpy()
    cat[nB > 1] = "split"
    one = nB == 1
    b_na_for_one = a_cat.index.to_series().map(matched_b_nA).to_numpy()
    cat[one & (b_na_for_one == 1)] = "1:1"
    cat[one & (b_na_for_one > 1)] = "merge"
    a_cat["category"] = cat

    pairs_1to1 = singles.loc[singles["b_nA"].eq(1), ["ia", "ib"]].reset_index(drop=True)
    return a_cat, pairs_1to1


def category_summary(a_cat: pd.DataFrame) -> pd.DataFrame:
    """Overall + per-label category fractions for one ordered pair (A vs B)."""
    rows = []
    total = a_cat["category"].value_counts()
    rows.append({"class": "ALL", "n": int(len(a_cat)),
                 **{c: int(total.get(c, 0)) for c in CATEGORIES}})
    for label, grp in a_cat.groupby("label"):
        vc = grp["category"].value_counts()
        rows.append({"class": str(label), "n": int(len(grp)),
                     **{c: int(vc.get(c, 0)) for c in CATEGORIES}})
    out = pd.DataFrame(rows)
    for c in CATEGORIES:
        out[f"{c}_frac"] = (out[c] / out["n"]).round(4)
    return out
