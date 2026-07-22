"""Central path/config resolution.

All code resolves filesystem locations through this module so that a single
`configs/paths.yaml` (plus environment-variable overrides) controls where the
study reads PCAPs and writes intermediate artifacts.

Layout produced under ``data_root``::

    <data_root>/extracted/<dataset>/<tool>/<capture>.<ext>   # raw tool output
    <data_root>/canonical/<dataset>/<tool>/<capture>.parquet # canonical schema

In-repo (small, versioned) inputs::

    data/labels/<dataset>/rules.yaml
    configs/**.yaml
    results/{metrics,tables,figures}/
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml

# repo root = three parents up from this file: src/nids_xstudy/config.py -> repo
REPO_ROOT = Path(__file__).resolve().parents[2]
PATHS_YAML = REPO_ROOT / "configs" / "paths.yaml"


@lru_cache(maxsize=1)
def _raw() -> dict:
    if PATHS_YAML.exists():
        with open(PATHS_YAML, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    return {}


def _abs(p: str | os.PathLike) -> Path:
    """Resolve a possibly-relative config path against the repo root."""
    path = Path(p)
    return path if path.is_absolute() else (REPO_ROOT / path)


def pcap_root(dataset: str = "cicids2017") -> Path:
    """Directory holding the raw input PCAPs for ``dataset``."""
    if dataset == "cicids2017":
        env = os.environ.get("NIDS_PCAP_ROOT")
        if env:
            return Path(env)
    root = _raw().get("pcaps", {}).get(dataset)
    if root is None:
        raise KeyError(f"No pcap root configured for dataset {dataset!r}")
    return Path(root)


def data_root() -> Path:
    env = os.environ.get("NIDS_DATA_ROOT")
    if env:
        return Path(env)
    return Path(_raw().get("data_root", REPO_ROOT / "data"))


def extracted_dir(dataset: str, tool: str) -> Path:
    d = data_root() / "extracted" / dataset / tool
    d.mkdir(parents=True, exist_ok=True)
    return d


def canonical_dir(dataset: str, tool: str) -> Path:
    d = data_root() / "canonical" / dataset / tool
    d.mkdir(parents=True, exist_ok=True)
    return d


def labeled_dir(dataset: str, tool: str) -> Path:
    d = data_root() / "labeled" / dataset / tool
    d.mkdir(parents=True, exist_ok=True)
    return d


@lru_cache(maxsize=None)
def dataset_spec(dataset: str) -> dict:
    """Load configs/datasets/<dataset>.yaml (capture -> pcap filename map)."""
    p = REPO_ROOT / "configs" / "datasets" / f"{dataset}.yaml"
    if not p.exists():
        return {}
    with open(p, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def pcap_for(dataset: str, capture: str) -> Path:
    """Resolve a capture name (e.g. 'Tuesday') to its PCAP path."""
    captures = dataset_spec(dataset).get("captures", {})
    fname = captures.get(capture)
    if fname is None:
        raise KeyError(f"capture {capture!r} not in configs/datasets/{dataset}.yaml")
    return pcap_root(dataset) / fname


def captures(dataset: str) -> list[str]:
    return list(dataset_spec(dataset).get("captures", {}).keys())


def labels_dir(dataset: str) -> Path:
    return _abs(_raw().get("labels_dir", "data/labels")) / dataset


def results_dir() -> Path:
    return _abs(_raw().get("results_dir", "results"))


def rules_path(dataset: str) -> Path:
    return labels_dir(dataset) / "rules.yaml"
