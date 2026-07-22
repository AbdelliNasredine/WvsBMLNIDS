"""Tranalyzer smoke test (Docker): assert ground truths on the synthetic PCAP.

Requires the built ``nids-xstudy/tranalyzer:0.9.4`` image; skips cleanly
otherwise. Tranalyzer's tcpFlags plugin reports aggregate flag bitfields, not
per-direction counts, so canonical flag columns are <NA> and not asserted here.
"""
from __future__ import annotations

import pandas as pd
import pytest

from fixtures.smoke import GROUND_TRUTH as GT
from nids_xstudy import canonical as C
from nids_xstudy.extraction import _docker
from nids_xstudy.extraction.run_tranalyzer import IMAGE

pytestmark = pytest.mark.docker

if not _docker.docker_available() or not _docker.image_exists(IMAGE):
    pytest.skip(f"Docker or image {IMAGE} unavailable", allow_module_level=True)


@pytest.fixture(scope="module")
def flows(smoke_pcap, tmp_path_factory) -> pd.DataFrame:
    from nids_xstudy.extraction.run_tranalyzer import extract
    out = tmp_path_factory.mktemp("t2") / "smoke.parquet"
    return C.read(extract(smoke_pcap, dataset="smoke", capture="smoke", out_path=out))


def _pick(df, key):
    s, sp, d, dp, pr = key
    return df[(df.src_ip == s) & (df.src_port == sp) & (df.dst_ip == d)
              & (df.dst_port == dp) & (df.proto == pr)]


def test_one_flow_per_five_tuple(flows):
    # B (reverse) duplicates dropped -> 24 flows for 24 five-tuples.
    assert len(flows) == GT["n_five_tuples"]


def test_http_directional_counts(flows):
    gt = GT["http"]
    r = _pick(flows, gt["key"])
    assert len(r) == 1
    assert r.iloc[0].pkts_fwd == gt["pkts_fwd"]
    assert r.iloc[0].pkts_bwd == gt["pkts_bwd"]


def test_dns_flow(flows):
    r = _pick(flows, GT["dns"]["key"])
    assert len(r) == 1
    assert r.iloc[0].proto == 17
    assert r.iloc[0].pkts_fwd == 1 and r.iloc[0].pkts_bwd == 1


def test_syn_scan(flows):
    gt = GT["scan"]
    sc = flows[(flows.src_ip == gt["src_ip"]) & (flows.dst_ip == gt["dst_ip"])]
    assert len(sc) == gt["n_ports"]
    assert (sc.pkts_fwd == 1).all()
    assert (sc.pkts_bwd.fillna(0) == 0).all()


def test_long_session_single_flow(flows):
    # Like Zeek (and unlike NFStream's 120s idle split), Tranalyzer keeps the
    # long session as one flow — a flow-segmentation divergence.
    assert len(_pick(flows, GT["long_session"]["key"])) == 1
