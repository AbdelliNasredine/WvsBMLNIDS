"""NFStream smoke test: assert known ground truths on the synthetic PCAP.

This is the Phase-0 acceptance gate for the NFStream runner (plan section 4):
the SYN scan produces N single-packet flows, the RST flow's flags are correct,
the long session splits at the idle timeout, etc.
"""
from __future__ import annotations

import pandas as pd
import pytest

from fixtures.smoke import GROUND_TRUTH
from nids_xstudy import canonical as C

pytest.importorskip("nfstream")


@pytest.fixture(scope="module")
def flows(smoke_pcap, tmp_path_factory) -> pd.DataFrame:
    from nids_xstudy.extraction.run_nfstream import extract
    out = tmp_path_factory.mktemp("nf") / "smoke.parquet"
    path = extract(
        smoke_pcap, dataset="smoke", capture="smoke",
        idle_timeout=GROUND_TRUTH["idle_timeout_s"], out_path=out,
    )
    return C.read(path)


def _pick(df, key):
    src_ip, src_port, dst_ip, dst_port, proto = key
    m = df[(df.src_ip == src_ip) & (df.src_port == src_port)
           & (df.dst_ip == dst_ip) & (df.dst_port == dst_port) & (df.proto == proto)]
    return m


@pytest.mark.smoke
def test_flow_count_at_idle120(flows):
    # Long session splits into 2 at 120s idle -> total 25 flows.
    assert len(flows) == GROUND_TRUTH["n_flows_idle120"]


@pytest.mark.smoke
def test_http_flow(flows):
    gt = GROUND_TRUTH["http"]
    m = _pick(flows, gt["key"])
    assert len(m) == 1, "expected exactly one HTTP flow"
    r = m.iloc[0]
    assert r.pkts_fwd == gt["pkts_fwd"]
    assert r.pkts_bwd == gt["pkts_bwd"]
    assert r.syn_fwd == gt["syn_fwd"] and r.syn_bwd == gt["syn_bwd"]
    assert r.fin_fwd == gt["fin_fwd"] and r.fin_bwd == gt["fin_bwd"]
    assert r.rst_fwd == 0 and r.rst_bwd == 0


@pytest.mark.smoke
def test_dns_flow(flows):
    gt = GROUND_TRUTH["dns"]
    m = _pick(flows, gt["key"])
    assert len(m) == 1
    r = m.iloc[0]
    assert r.proto == 17
    assert r.pkts_fwd == 1 and r.pkts_bwd == 1


@pytest.mark.smoke
def test_rst_flow(flows):
    gt = GROUND_TRUTH["rst"]
    m = _pick(flows, gt["key"])
    assert len(m) == 1
    r = m.iloc[0]
    assert r.rst_bwd == 1, "responder RST must be counted in bwd direction"
    assert r.rst_fwd == 0
    assert r.pkts_fwd == gt["pkts_fwd"] and r.pkts_bwd == gt["pkts_bwd"]


@pytest.mark.smoke
def test_syn_scan_produces_single_packet_flows(flows):
    gt = GROUND_TRUTH["scan"]
    scan = flows[(flows.src_ip == gt["src_ip"]) & (flows.dst_ip == gt["dst_ip"])
                 & (flows.src_port == gt["src_port"])]
    assert len(scan) == gt["n_ports"], "one flow per scanned port"
    assert set(scan.dst_port.astype(int)) == set(gt["dst_ports"])
    assert (scan.pkts_fwd == 1).all()
    assert (scan.pkts_bwd.fillna(0) == 0).all()
    assert (scan.syn_fwd == 1).all()


@pytest.mark.smoke
def test_long_session_splits_at_idle_timeout(flows):
    gt = GROUND_TRUTH["long_session"]
    m = _pick(flows, gt["key"])
    assert len(m) == gt["n_flows_at_idle120"], (
        "long session should split into 2 flows at 120s idle timeout"
    )
