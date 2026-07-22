"""Black-box (NFM) extractor wrappers: assemble -> tokenize -> embed.

Each GPU wrapper subclasses :class:`nids_xstudy.nfm.base.NFM` and consumes the
assembler's uint8 packet images. Imports are numpy-only at module load
(torch/model libs are lazy) so this package is importable from the CPU assembly
env; the GPU is required only at ``embed`` time.

Use :func:`get_extractor` to instantiate any model by name.
"""
from .base import NFM

# name -> (submodule, class). Lazy so importing the package pulls no torch.
# (nPrint was removed from the study; NetMamba never integrated -- see NFM_CARDS.md.)
_REGISTRY = {
    "raw-cnn": ("raw_cnn", "RawCNNExtractor"),
    "yatc": ("yatc", "YaTCExtractor"),
    "etbert": ("etbert", "ETBERTExtractor"),
    "netfound": ("netfound", "NetFoundExtractor"),
}

# GPU models embed uint8 packet images ([N, max_pkts, max_bytes]) via NFM.embed().
GPU_MODELS = ["raw-cnn", "yatc", "etbert", "netfound"]
CPU_MODELS = []  # kept for import compatibility (was ["nprint"])
ALL_MODELS = GPU_MODELS + CPU_MODELS


def get_extractor(name: str, **kwargs):
    """Instantiate an extractor by registry name (lazy import)."""
    import importlib
    if name not in _REGISTRY:
        raise ValueError(f"unknown extractor {name!r}; known: {list(_REGISTRY)}")
    submod, cls = _REGISTRY[name]
    module = importlib.import_module(f"{__name__}.{submod}")
    return getattr(module, cls)(**kwargs)


__all__ = ["NFM", "get_extractor", "GPU_MODELS", "CPU_MODELS", "ALL_MODELS"]
