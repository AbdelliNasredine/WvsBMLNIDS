"""Raw-bytes 1D-CNN (DeepPacket-style) baseline.

Trained end-to-end from scratch in Phase B2 -- the control that answers "is
pretraining actually buying anything?". As an NFM wrapper it also exposes its
penultimate layer as a (here randomly initialized) frozen embedding, which for
Phase B0 serves to validate the assembler -> build -> GPU-embed -> cache path on
the ROCm stack. Torch is imported lazily.
"""
from __future__ import annotations

import numpy as np

from .base import NFM

EMB_DIM = 128


def _build_module(in_len: int, emb_dim: int, n_classes: int | None, seed: int):
    import torch
    import torch.nn as nn
    torch.manual_seed(seed)

    class RawCNN(nn.Module):
        def __init__(self):
            super().__init__()
            self.features = nn.Sequential(
                nn.Conv1d(1, 32, kernel_size=25, padding=12), nn.ReLU(),
                nn.MaxPool1d(3),
                nn.Conv1d(32, 64, kernel_size=25, padding=12), nn.ReLU(),
                nn.MaxPool1d(3),
                nn.AdaptiveAvgPool1d(16),
            )
            self.embed = nn.Sequential(nn.Flatten(), nn.Linear(64 * 16, emb_dim), nn.ReLU())
            self.head = nn.Linear(emb_dim, n_classes) if n_classes else None

        def forward(self, x, return_embedding=True):
            z = self.embed(self.features(x))
            if return_embedding or self.head is None:
                return z
            return self.head(z)

    return RawCNN()


class RawCNNExtractor(NFM):
    name = "raw-cnn"
    dim = EMB_DIM
    checkpoint_hash = None  # trained from scratch; no pretrained checkpoint

    def __init__(self, max_pkts: int = 32, max_bytes: int = 128, seed: int = 0):
        super().__init__()
        self.in_len = max_pkts * max_bytes
        self.seed = seed

    def load(self, device: str = "cuda"):
        import torch
        self.device = device
        self.model = _build_module(self.in_len, self.dim, None, self.seed).to(device)
        return self

    def build_batch(self, images_u8: np.ndarray):
        import torch
        b = images_u8.reshape(images_u8.shape[0], -1).astype(np.float32) / 255.0
        return torch.from_numpy(b).unsqueeze(1).to(self.device)  # [B, 1, in_len]

    def forward(self, batch):
        return self.model(batch, return_embedding=True)
