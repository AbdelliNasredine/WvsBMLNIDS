"""Reference flow assembler vs the smoke-PCAP ground truth (Phase B0 gate)."""
from pathlib import Path

import numpy as np
import pytest

from nids_xstudy.assembly import ASSEMBLY_DEFAULTS, AssemblyConfig, assemble
from tests.fixtures import smoke


@pytest.fixture(scope="module")
def assembled(tmp_path_factory):
    p = tmp_path_factory.mktemp("asm") / "smoke.pcap"
    smoke.build_pcap(p)
    return assemble(p)


def test_flow_count_idle120(assembled):
    meta, _ = assembled
    assert len(meta) == smoke.GROUND_TRUTH["n_flows_idle120"]  # long session splits -> 25


def test_image_shape_and_dtype(assembled):
    meta, imgs = assembled
    assert imgs.shape == (len(meta), ASSEMBLY_DEFAULTS.max_pkts, ASSEMBLY_DEFAULTS.max_bytes)
    assert imgs.dtype == np.uint8


def test_http_directions(assembled):
    meta, _ = assembled
    h = meta[(meta.src_ip == smoke.CLIENT) & (meta.dst_port == 80)].iloc[0]
    assert (h.pkts_fwd, h.pkts_bwd) == (6, 4)
    assert h.seq_len == 10 and len(h.dirs) == 10


def test_rst_flow(assembled):
    meta, _ = assembled
    r = meta[(meta.src_ip == smoke.CLIENT3) & (meta.dst_port == 8080)].iloc[0]
    assert (r.pkts_fwd, r.pkts_bwd) == (3, 2)


def test_scan_flows(assembled):
    meta, _ = assembled
    sc = meta[meta.src_ip == smoke.SCANNER]
    assert len(sc) == smoke.SCAN_N_PORTS
    assert (sc.pkts_fwd == 1).all() and (sc.pkts_bwd == 0).all()


def test_long_session_splits(assembled):
    meta, _ = assembled
    ls = meta[(meta.src_ip == smoke.CLIENT2) & (meta.dst_port == 443)]
    assert len(ls) == 2


def test_active_timeout_keeps_one_flow():
    """With a huge idle timeout the long session should NOT split."""
    p = Path(smoke.build_pcap(Path(smoke.PCAP_PATH)))
    cfg = AssemblyConfig(idle_timeout=10_000, active_timeout=10_000)
    meta, _ = assemble(p, cfg)
    ls = meta[(meta.src_ip == smoke.CLIENT2) & (meta.dst_port == 443)]
    assert len(ls) == 1


def test_no_nans(assembled):
    meta, _ = assembled
    assert not meta[["t_start", "t_end", "duration", "proto"]].isna().any().any()
