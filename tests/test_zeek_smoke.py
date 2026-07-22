"""Zeek smoke test (Docker): assert ground truths + document divergence.

Requires the built ``nids-xstudy/zeek:6.0.0`` image and a running Docker daemon;
skips cleanly otherwise so the default `pytest` run stays green without Docker.
"""
from __future__ import annotations

import pandas as pd
import pytest

from fixtures.smoke import GROUND_TRUTH as GT
from nids_xstudy import canonical as C
from nids_xstudy.extraction import _docker
from nids_xstudy.extraction.run_zeek import IMAGE

pytestmark = pytest.mark.docker

if not _docker.docker_available() or not _docker.image_exists(IMAGE):
    pytest.skip(f"Docker or image {IMAGE} unavailable", allow_module_level=True)


@pytest.fixture(scope="module")
def flows(smoke_pcap, tmp_path_factory) -> pd.DataFrame:
    from nids_xstudy.extraction.run_zeek import extract
    out = tmp_path_factory.mktemp("zeek") / "smoke.parquet"
    return C.read(extract(smoke_pcap, dataset="smoke", capture="smoke", out_path=out))


def _pick(df, key):
    s, sp, d, dp, pr = key
    return df[(df.src_ip == s) & (df.src_port == sp) & (df.dst_ip == d)
              & (df.dst_port == dp) & (df.proto == pr)]


def test_http_flag_counts(flows):
    gt = GT["http"]
    r = _pick(flows, gt["key"])
    assert len(r) == 1
    r = r.iloc[0]
    assert r.pkts_fwd == gt["pkts_fwd"] and r.pkts_bwd == gt["pkts_bwd"]
    assert r.syn_fwd == 1 and r.syn_bwd == 1
    assert r.fin_fwd == 1 and r.fin_bwd == 1
    assert r.psh_fwd == 1 and r.psh_bwd == 1


def test_rst_flow_flag_accounting(flows):
    # Zeek's stateful tracker may split this fast synthetic RST connection into a
    # lone-SYN S0 + a flipped remainder; validate the RST FLAG ACCOUNTING across
    # the 4-tuple (the point of the test) rather than the segmentation, which is
    # a synthetic-traffic artifact. NFStream keeps it as one flow (see its test).
    s, sp, d, dp, pr = GT["rst"]["key"]
    r = flows[(flows.src_ip == s) & (flows.dst_ip == d) & (flows.dst_port == dp)]
    assert r.rst_bwd.fillna(0).sum() == 1, "exactly one backward RST expected"
    assert r.rst_fwd.fillna(0).sum() == 0
    assert r.syn_fwd.fillna(0).sum() == 1


def test_dns_flow(flows):
    r = _pick(flows, GT["dns"]["key"])
    assert len(r) == 1
    assert r.iloc[0].proto == 17
    assert r.iloc[0].pkts_fwd == 1 and r.iloc[0].pkts_bwd == 1


def test_syn_scan(flows):
    gt = GT["scan"]
    sc = flows[(flows.src_ip == gt["src_ip"]) & (flows.dst_ip == gt["dst_ip"])
               & (flows.src_port == gt["src_port"])]
    assert len(sc) == gt["n_ports"]
    assert (sc.pkts_fwd == 1).all()
    assert (sc.syn_fwd == 1).all()


def test_long_session_segmentation_diverges_from_nfstream(flows):
    """Zeek keeps the long session as ONE flow where NFStream splits it into two
    at the 120s idle timeout — a flow-accounting divergence (RQ3) surfacing even
    on the smoke fixture."""
    r = _pick(flows, GT["long_session"]["key"])
    assert len(r) == 1
