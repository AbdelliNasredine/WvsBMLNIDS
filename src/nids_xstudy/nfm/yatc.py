"""YaTC frozen-embedding extractor (black-box NFM).

YaTC ("Yet Another Traffic Classifier", AAAI'23) is a masked-autoencoder traffic
transformer over a *Multi-level Flow Representation* (MFR): the first 5 packets of
a flow, each rendered as 80 header bytes + 240 payload bytes, laid out as a single
40x40 grayscale image. This wrapper loads YaTC's own pretrained MAE encoder and
exposes its pooled encoder output as a frozen 192-d embedding, one vector per flow.

MFR construction reuses YaTC's exact 40x40 layout (``vendor/nfm/yatc/data_process.py``):
per packet the header slot is the IP+transport header bytes (padded/truncated to 80)
and the payload slot is the transport payload (padded/truncated to 240). We reconstruct
that split from the reference assembler's per-packet IP bytes by parsing the IP IHL and
the TCP data-offset / UDP fixed header length, driven off the shared assembler so flow
segmentation is the study's reference policy. (Assemble with ``max_pkts>=5`` and
``max_bytes>=320``.)

Fidelity note: YaTC's original ``read_MFR_bytes`` derives the boundary from scapy's
``Raw`` layer, so whenever scapy dissects an application protocol above L4 (DNS, DHCP,
NTP, ...) that app-header ends up in YaTC's *header* slot. Raw assembler bytes carry no
layer structure, so we split at the transport boundary instead. This is byte-identical
to YaTC for all non-dissected traffic (e.g. 43/45 packets in the smoke fixture; the 2
that differ are DNS-over-UDP, where the 12-byte DNS header lands on the other side of
the boundary). All the same bytes are present; only that boundary shifts for such flows.

Torch is imported lazily (numpy-only at module top) so this module imports from a
CPU/scapy env; the heavy work runs under the ROCm ``nfm-yatc`` env. Attention is
forced onto the pure-math SDPA backend (no Triton/flash/xformers, per ROCm rules).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import numpy as np

from .base import NFM

# Repo-relative location of the pinned YaTC checkout + its pretrained checkpoint.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_YATC_DIR = _REPO_ROOT / "vendor" / "nfm" / "yatc"
_DEFAULT_CKPT = _YATC_DIR / "output_dir" / "pretrained-model.pth"

# MFR geometry (fixed by the YaTC architecture / pretrained checkpoint).
MFR_PKTS = 5            # packets per flow rendered into the image
HDR_BYTES = 80         # header bytes per packet (160 hex chars)
PAY_BYTES = 240        # payload bytes per packet (480 hex chars)
PKT_BYTES = HDR_BYTES + PAY_BYTES  # 320 -> 5 packets * 320 = 1600 = 40*40
IMG_HW = 40
EMB_DIM = 192

# sha256 of YaTC's published pretrained-model.pth (Google Drive, see module docs).
CHECKPOINT_SHA256 = "66314aa57d4364bad0228835a181158f819d10c857936fbbdbae6dc483211fc6"


def _build_mfr(images_u8: np.ndarray) -> np.ndarray:
    """Reconstruct YaTC MFR images [B, 40, 40] uint8 from assembler packet bytes.

    ``images_u8`` is [B, max_pkts, max_bytes] of raw IP-layer bytes (the reference
    assembler's output). We take the first 5 packets and, per packet, split into an
    80-byte header slot (IP + L4 header) and a 240-byte payload slot (L4 payload),
    exactly mirroring ``data_process.read_MFR_bytes``.
    """
    if images_u8.ndim != 3:
        raise ValueError(f"expected [B, P, L] images, got {images_u8.shape}")
    b, p, ell = images_u8.shape

    # first MFR_PKTS packets, zero-pad the packet axis if the flow had fewer
    imgs = images_u8[:, :MFR_PKTS, :]
    if p < MFR_PKTS:
        pad = np.zeros((b, MFR_PKTS - p, ell), np.uint8)
        imgs = np.concatenate([imgs, pad], axis=1)

    m = b * MFR_PKTS
    flat = imgs.reshape(m, ell).astype(np.uint8)

    # right-pad the byte axis so every header/payload index is in-bounds; padding
    # with zeros matches YaTC's own zero padding of short headers/payloads.
    width = max(HDR_BYTES + PAY_BYTES + 60, ell)  # 60 = max IP+L4 option slack
    pp = np.zeros((m, width), np.uint8)
    pp[:, :ell] = flat
    rows = np.arange(m)

    ihl = (pp[:, 0] & 0x0F).astype(np.int64) * 4          # IP header length (bytes)
    proto = pp[:, 9].astype(np.int64)                     # IP protocol
    is_tcp = proto == 6
    is_udp = proto == 17

    # TCP data offset lives in the high nibble of byte (ihl + 12)
    doff_idx = np.clip(ihl + 12, 0, width - 1)
    tcp_hlen = (pp[rows, doff_idx].astype(np.int64) >> 4) * 4

    l4_len = np.where(is_tcp, tcp_hlen, np.where(is_udp, 8, 0))
    header_len = ihl + l4_len
    # non-TCP/UDP (and empty/pad rows): treat the whole packet as header, no payload
    header_len = np.where(is_tcp | is_udp, header_len, width).astype(np.int64)

    # header slot: first `header_len` bytes, zeroed past the true header, capped 80
    hcol = np.arange(HDR_BYTES)[None, :]
    header = pp[:, :HDR_BYTES] * (hcol < header_len[:, None])

    # payload slot: 240 bytes starting at header_len (zeros where out of range)
    pcol = np.arange(PAY_BYTES)[None, :]
    pidx = np.clip(header_len[:, None] + pcol, 0, width - 1)
    payload = np.take_along_axis(pp, pidx, axis=1)

    per_pkt = np.concatenate([header, payload], axis=1).astype(np.uint8)  # [m, 320]
    return per_pkt.reshape(b, MFR_PKTS * PKT_BYTES).reshape(b, IMG_HW, IMG_HW)


class YaTCExtractor(NFM):
    """Frozen YaTC MAE-encoder embeddings (192-d), one vector per flow.

    The embedding is the encoder's pooled output. ``pool='mean'`` (default) averages
    the encoder's patch tokens (the standard MAE global-pool feature); ``pool='cls'``
    returns the class token. Both are 192-d and deterministic (encoder self-attention
    is permutation-invariant, so the mask_ratio=0 token shuffle does not affect output).
    """

    name = "yatc"
    dim = EMB_DIM
    checkpoint_hash = CHECKPOINT_SHA256

    def __init__(self, checkpoint: str | os.PathLike | None = None, pool: str = "mean"):
        super().__init__()
        if pool not in ("mean", "cls"):
            raise ValueError(f"pool must be 'mean' or 'cls', got {pool!r}")
        self.pool = pool
        env_ckpt = os.environ.get("NIDS_YATC_CKPT")
        self.checkpoint = Path(checkpoint or env_ckpt or _DEFAULT_CKPT)
        self.random_init = False  # set True if no checkpoint is found at load()

    def load(self, device: str = "cuda"):
        import torch

        if str(_YATC_DIR) not in sys.path:
            sys.path.insert(0, str(_YATC_DIR))  # for `import models_YaTC` / `util.*`
        import models_YaTC  # patched: ROCm-safe timm shim, no skimage

        model = models_YaTC.MAE_YaTC()
        if self.checkpoint.is_file():
            ck = torch.load(str(self.checkpoint), map_location="cpu", weights_only=False)
            state = ck["model"] if isinstance(ck, dict) and "model" in ck else ck
            msg = model.load_state_dict(state, strict=False)
            enc_missing = [k for k in msg.missing_keys
                           if not k.startswith(("decoder", "mask_token"))]
            assert not enc_missing, f"missing encoder weights: {enc_missing}"
            self.checkpoint_hash = CHECKPOINT_SHA256
        else:
            # Checkpoint unavailable/gated: validate the pipeline with random init.
            self.random_init = True
            self.checkpoint_hash = None

        self.device = device
        self.model = model.to(device).eval()
        return self

    def build_batch(self, images_u8: np.ndarray):
        import torch

        mfr = _build_mfr(np.ascontiguousarray(images_u8, dtype=np.uint8))  # [B,40,40] u8
        # YaTC transform: ToTensor (/255 -> [0,1]) then Normalize(mean=.5, std=.5)
        x = mfr.astype(np.float32) / 127.5 - 1.0
        t = torch.from_numpy(x).unsqueeze(1)  # [B, 1, 40, 40]
        return t.to(self.device)

    def forward(self, batch):
        import torch
        from torch.nn.attention import sdpa_kernel, SDPBackend

        # Force the pure-math SDPA kernel: ROCm flash/mem-efficient kernels are
        # experimental on this GPU; math is exact and dependency-free.
        with sdpa_kernel([SDPBackend.MATH]):
            latent, _, _ = self.model.forward_encoder(batch, 0.0)  # [B, 401, 192]
        if self.pool == "cls":
            return latent[:, 0, :]
        return latent[:, 1:, :].mean(dim=1)  # mean over patch tokens
