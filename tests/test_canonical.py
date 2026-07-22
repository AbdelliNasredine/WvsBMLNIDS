"""Schema-level tests for the canonical contract (no external tools needed)."""
from __future__ import annotations

import pandas as pd
import pytest

from nids_xstudy import canonical as C


def _minimal_row(**over):
    row = {
        "src_ip": "10.0.0.1", "src_port": 1234, "dst_ip": "10.0.0.2",
        "dst_port": 80, "proto": 6,
        "t_start": 100.0, "t_end": 101.0, "duration": 1.0,
        "pkts_fwd": 3, "pkts_bwd": 2, "bytes_fwd": 300, "bytes_bwd": 200,
        "tool": "t", "dataset": "d", "capture": "c", "flow_id": "0",
    }
    row.update(over)
    return row


def test_empty_frame_has_all_core_columns():
    df = C.empty_frame()
    for col in C.CORE_COLUMNS:
        assert col in df.columns


def test_coerce_adds_missing_flag_columns_as_na():
    df = pd.DataFrame([_minimal_row()])
    out = C.coerce_schema(df)
    assert out["syn_fwd"].isna().all()
    assert list(out.columns[: len(C.FLOW_KEY)]) == C.FLOW_KEY


def test_validate_rejects_negative_counts():
    df = pd.DataFrame([_minimal_row(pkts_fwd=-1)])
    with pytest.raises(ValueError):
        C.validate(C.coerce_schema(df), strict=True)


def test_validate_rejects_t_end_before_start():
    df = pd.DataFrame([_minimal_row(t_start=200.0, t_end=100.0, duration=-100.0)])
    with pytest.raises(ValueError):
        C.validate(C.coerce_schema(df), strict=True)


def test_non_canonical_column_rejected():
    df = pd.DataFrame([_minimal_row()])
    df["random_extra"] = 1
    with pytest.raises(ValueError):
        C.coerce_schema(df)


def test_tool_prefixed_columns_allowed_and_preserved():
    df = pd.DataFrame([_minimal_row()])
    df["tool_native_feature"] = 42
    out = C.coerce_schema(df)
    assert "tool_native_feature" in out.columns


def test_proto_coercion():
    assert C.proto_to_number("tcp") == 6
    assert C.proto_to_number("UDP") == 17
    assert C.proto_to_number(6) == 6
    assert C.proto_to_number("6") == 6
    assert C.proto_to_number(None) is None


def test_bidirectional_key_is_direction_independent():
    a = C.bidirectional_key({"src_ip": "1.1.1.1", "src_port": 5, "dst_ip": "2.2.2.2", "dst_port": 80, "proto": 6})
    b = C.bidirectional_key({"src_ip": "2.2.2.2", "src_port": 80, "dst_ip": "1.1.1.1", "dst_port": 5, "proto": 6})
    assert a == b


def test_roundtrip_parquet(tmp_path):
    df = pd.DataFrame([_minimal_row(), _minimal_row(src_port=2222)])
    df["tool_x"] = [1.0, 2.0]
    p = tmp_path / "f.parquet"
    C.write(df, p)
    back = C.read(p)
    assert len(back) == 2
    assert "tool_x" in back.columns
    assert back["src_ip"].iloc[0] == "10.0.0.1"
