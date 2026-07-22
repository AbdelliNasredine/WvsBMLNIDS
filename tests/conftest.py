"""Test bootstrap: make ``src/`` importable and provide the smoke fixture."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

sys.path.insert(0, str(Path(__file__).resolve().parent))  # for `fixtures` pkg


@pytest.fixture(scope="session")
def smoke_pcap(tmp_path_factory) -> Path:
    """Build the synthetic smoke PCAP once per test session."""
    from fixtures.smoke import build_pcap
    out = tmp_path_factory.mktemp("smoke") / "smoke.pcap"
    return build_pcap(out)
