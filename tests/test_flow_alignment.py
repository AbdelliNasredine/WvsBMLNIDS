"""Unit tests for the cross-tool flow-alignment matcher."""
from __future__ import annotations

import pandas as pd

from nids_xstudy import canonical as C
from nids_xstudy.flow_alignment.align import bidir_key_series, match_pair


def _flow(ts, te, sip="10.0.0.1", sp=1000, dip="10.0.0.2", dp=80, proto=6, label="BENIGN"):
    row = {"src_ip": sip, "src_port": sp, "dst_ip": dip, "dst_port": dp, "proto": proto,
           "t_start": ts, "t_end": te, "duration": te - ts,
           "pkts_fwd": 5, "pkts_bwd": 3, "bytes_fwd": 500, "bytes_bwd": 300,
           "tool": "t", "dataset": "d", "capture": "c", "flow_id": "0"}
    df = C.coerce_schema(pd.DataFrame([row]))
    df["label"] = label
    return df


def _cat(dfA, dfB):
    a_cat, _ = match_pair(dfA, dfB)
    return list(a_cat["category"])


def test_bidir_key_direction_independent():
    a = bidir_key_series(_flow(0, 1, "1.1.1.1", 5, "2.2.2.2", 80)).iloc[0]
    b = bidir_key_series(_flow(0, 1, "2.2.2.2", 80, "1.1.1.1", 5)).iloc[0]
    assert a == b


def test_one_to_one():
    A = _flow(0, 10)
    B = _flow(0, 10)
    assert _cat(A, B) == ["1:1"]


def test_split_one_A_many_B():
    A = _flow(0, 10)
    B = pd.concat([_flow(0, 4), _flow(5, 10)], ignore_index=True)
    assert _cat(A, B) == ["split"]


def test_merge_many_A_one_B():
    A = pd.concat([_flow(0, 4), _flow(5, 10)], ignore_index=True)
    B = _flow(0, 10)
    assert _cat(A, B) == ["merge", "merge"]


def test_unmatched_no_time_overlap():
    A = _flow(0, 10)
    B = _flow(20, 30)  # same key, disjoint time -> unmatched
    assert _cat(A, B) == ["unmatched"]


def test_unmatched_different_key():
    A = _flow(0, 10, dp=80)
    B = _flow(0, 10, dp=443)  # different key
    assert _cat(A, B) == ["unmatched"]
