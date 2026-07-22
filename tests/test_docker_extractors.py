"""Generic cross-tool Docker smoke test.

For every extractor whose image is built, run it on the synthetic PCAP and assert
the universal invariants: it produces a schema-valid canonical frame and locates
the HTTP connection (10.0.0.10:40001 -> web:80). Per-direction packet counts are
checked only for tools that expose them (not go-flows, which reports merged
totals). Tools whose image is absent are skipped, so this passes without Docker.
"""
from __future__ import annotations

import importlib

import pytest

from fixtures.smoke import GROUND_TRUTH as GT
from nids_xstudy import canonical as C
from nids_xstudy.extraction import _docker

pytestmark = pytest.mark.docker

# tool key -> (runner module, extract kwargs, exposes_per_direction_counts)
DOCKER_TOOLS = {
    "zeek": ("run_zeek", {}, True),
    "argus": ("run_argus", {}, True),
    "tranalyzer": ("run_tranalyzer", {}, True),
    "cicflowmeter-fixed": ("run_cicflowmeter", {"variant": "fixed"}, True),
    "go-flows": ("run_goflows", {}, False),   # merged counts only
    "yaf": ("run_yaf", {}, True),
    "joy": ("run_joy", {}, True),
}

if not _docker.docker_available():
    pytest.skip("Docker daemon unavailable", allow_module_level=True)


def _mod(name):
    return importlib.import_module(f"nids_xstudy.extraction.{name}")


@pytest.mark.parametrize("tool", list(DOCKER_TOOLS))
def test_extractor_smoke(tool, smoke_pcap, tmp_path_factory):
    modname, kwargs, per_dir = DOCKER_TOOLS[tool]
    mod = _mod(modname)
    image = getattr(mod, "IMAGE", None) or next(iter(getattr(mod, "IMAGE_BY_VARIANT", {}).values()), None)
    if image and not _docker.image_exists(image):
        pytest.skip(f"image {image} not built")
    out = tmp_path_factory.mktemp(tool.replace("/", "_")) / "smoke.parquet"
    df = C.read(mod.extract(smoke_pcap, dataset="smoke", capture="smoke", out_path=out, **kwargs))

    assert C.validate(df, strict=False) == [], f"{tool}: canonical invalid"
    assert len(df) > 0, f"{tool}: no flows"

    s, sp, d, dp, pr = GT["http"]["key"]
    http = df[(df.src_ip == s) & (df.dst_ip == d) & (df.dst_port == dp)]
    assert len(http) >= 1, f"{tool}: HTTP connection not found"
    if per_dir:
        # the primary HTTP flow should carry 6 fwd packets for tools that keep
        # the connection whole (CICFlowMeter-orig splits it; not tested here)
        assert (http["pkts_fwd"] == GT["http"]["pkts_fwd"]).any(), \
            f"{tool}: no HTTP flow with pkts_fwd={GT['http']['pkts_fwd']}"
