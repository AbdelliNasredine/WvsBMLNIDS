"""Tests for the shared labeling engine (logic only — synthetic rules/flows)."""
from __future__ import annotations

import pandas as pd
import pytest

from nids_xstudy import canonical as C
from nids_xstudy.labeling.engine import LabelRules, label_flows

RULES_SPEC = {
    "dataset": "test",
    "benign_label": "BENIGN",
    "timezone": {"capture_tz": "America/Halifax"},
    "attacks": [{
        "name": "FTP-Patator", "label": "FTP-Patator",
        "date": "2017-07-04", "start_local": "09:20:00", "end_local": "10:20:00",
        "tz": "America/Halifax",
        "attackers": ["172.16.0.1"], "victims": ["192.168.10.50"],
        "dst_ports": [21], "proto": [6],
    }],
}


@pytest.fixture(scope="module")
def rules() -> LabelRules:
    return LabelRules(RULES_SPEC)


def _flow(**over):
    row = {
        "src_ip": "172.16.0.1", "src_port": 55000, "dst_ip": "192.168.10.50",
        "dst_port": 21, "proto": 6,
        "t_start": 0.0, "t_end": 1.0, "duration": 1.0,
        "pkts_fwd": 5, "pkts_bwd": 3, "bytes_fwd": 500, "bytes_bwd": 300,
        "tool": "t", "dataset": "test", "capture": "c", "flow_id": "0",
    }
    row.update(over)
    return row


def test_windows_convert_adt_to_utc(rules):
    # 09:20 ADT (UTC-3) == 12:20 UTC
    r = rules.rules[0]
    from datetime import datetime, timezone
    dt = datetime.fromtimestamp(r.t_start, tz=timezone.utc)
    assert (dt.hour, dt.minute) == (12, 20)


def test_exact_match_inside_window(rules):
    win = rules.rules[0].t_start
    df = pd.DataFrame([_flow(t_start=win + 60, t_end=win + 120, duration=60)])
    out = label_flows(C.coerce_schema(df), rules)
    assert out.loc[0, "label"] == "FTP-Patator"
    assert out.loc[0, "binary_label"] == "ATTACK"
    assert out.loc[0, "label_confidence"] == "exact"


def test_direction_agnostic_ip_match(rules):
    """Flow oriented victim->attacker (service port on src) still matches."""
    win = rules.rules[0].t_start
    df = pd.DataFrame([_flow(
        src_ip="192.168.10.50", src_port=21, dst_ip="172.16.0.1", dst_port=55000,
        t_start=win + 60, t_end=win + 120, duration=60,
    )])
    out = label_flows(C.coerce_schema(df), rules)
    assert out.loc[0, "label"] == "FTP-Patator"


def test_window_edge_confidence(rules):
    """Flow straddling the window end is labeled but flagged window_edge."""
    r = rules.rules[0]
    df = pd.DataFrame([_flow(t_start=r.t_end - 10, t_end=r.t_end + 60, duration=70)])
    out = label_flows(C.coerce_schema(df), rules)
    assert out.loc[0, "label"] == "FTP-Patator"
    assert out.loc[0, "label_confidence"] == "window_edge"


def test_benign_by_exclusion_wrong_ip(rules):
    win = rules.rules[0].t_start
    df = pd.DataFrame([_flow(src_ip="10.9.9.9", t_start=win + 60, t_end=win + 90, duration=30)])
    out = label_flows(C.coerce_schema(df), rules)
    assert out.loc[0, "label"] == "BENIGN"
    assert out.loc[0, "label_confidence"] == "benign"


def test_benign_by_exclusion_wrong_time(rules):
    r = rules.rules[0]
    df = pd.DataFrame([_flow(t_start=r.t_end + 3600, t_end=r.t_end + 3660, duration=60)])
    out = label_flows(C.coerce_schema(df), rules)
    assert out.loc[0, "label"] == "BENIGN"


def test_wrong_port_not_matched(rules):
    win = rules.rules[0].t_start
    df = pd.DataFrame([_flow(dst_port=80, t_start=win + 60, t_end=win + 90, duration=30)])
    out = label_flows(C.coerce_schema(df), rules)
    assert out.loc[0, "label"] == "BENIGN"
