"""Common interface for black-box (NFM) extractors.

Every model wrapper turns the assembler's per-flow packet image into a fixed
embedding vector, ON THE GPU. The shared ``embed`` loop enforces the plan's
non-negotiables: it asserts the model actually lives on the accelerator (a
silent CPU fallback is the documented #1 failure mode on this ROCm stack),
checks for NaNs, and measures throughput (the first RQ-B6 datapoint). Torch is
imported lazily so this module can be inspected from the CPU (scapy) env.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod

import numpy as np


class NFM(ABC):
    """Base class for a frozen neural feature extractor."""

    name: str = "base"
    dim: int | None = None
    checkpoint_hash: str | None = None

    def __init__(self):
        self.model = None
        self.device = None

    @abstractmethod
    def load(self, device: str = "cuda"):
        """Instantiate/​load the model onto ``device``. Sets self.model/self.device."""

    @abstractmethod
    def build_batch(self, images_u8: np.ndarray):
        """Turn a uint8 image batch [B, max_pkts, max_bytes] into model input
        tensor(s) on self.device (model-specific tokenization/normalization)."""

    @abstractmethod
    def forward(self, batch):
        """Return the embedding tensor [B, dim] for a built batch (no grad)."""

    def _assert_on_gpu(self):
        import torch
        assert torch.cuda.is_available(), "GPU/ROCm not available"
        params = list(self.model.parameters()) if hasattr(self.model, "parameters") else []
        if params:
            assert params[0].is_cuda, f"{self.name}: model is on CPU (silent fallback)"

    def embed(self, images_u8: np.ndarray, device: str = "cuda",
              batch_size: int = 256) -> dict:
        """Embed all flows. Returns dict with embeddings [N, dim] float32,
        device name, throughput (flows/s), and NaN/shape checks."""
        import torch
        if self.model is None:
            self.load(device)
        self._assert_on_gpu()
        self.model.eval()
        outs = []
        t0 = time.time()
        with torch.no_grad():
            for s in range(0, len(images_u8), batch_size):
                batch = self.build_batch(images_u8[s:s + batch_size])
                emb = self.forward(batch)
                outs.append(emb.detach().float().cpu().numpy())
        embs = np.concatenate(outs, axis=0) if outs else np.zeros((0, self.dim or 0), np.float32)
        dt = time.time() - t0
        return {
            "embeddings": embs.astype(np.float32),
            "device": torch.cuda.get_device_name(0),
            "n_flows": int(len(images_u8)),
            "dim": int(embs.shape[1]) if embs.size else (self.dim or 0),
            "flows_per_s": round(len(images_u8) / dt, 1) if dt > 0 else None,
            "has_nan": bool(np.isnan(embs).any()),
        }

    def provenance(self) -> dict:
        import torch
        return {"model": self.name, "dim": self.dim, "checkpoint_hash": self.checkpoint_hash,
                "torch": torch.__version__,
                "device": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "cpu"}
