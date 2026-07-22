"""ET-BERT frozen-embedding NFM wrapper.

ET-BERT (Lin et al., WWW'22) is a BERT pre-trained on encrypted-traffic
"BURST" datagrams tokenized as overlapping **hex-bigram** tokens (each token =
two adjacent bytes, i.e. 4 hex chars; sliding window with a 1-byte stride). This
wrapper turns the reference assembler's per-flow packet image into ET-BERT's own
token-id sequence and returns the pre-trained BERT's ``[CLS]`` hidden state as a
frozen 768-d embedding.

Design notes
------------
* We reuse ET-BERT's *bundled UER-py* code (``vendor/nfm/etbert/uer``) to build
  the BERT trunk (``WordPosSegEmbedding`` + ``TransformerEncoder``) and its
  ``BertTokenizer``/``Vocab`` for the exact wordpiece token->id mapping. The
  UER-format checkpoint is loaded directly (``strict=False`` skips the MLM
  target head); no HuggingFace conversion is performed.
* UER's self-attention is a plain ``matmul`` + ``softmax`` (see
  ``uer/layers/multi_headed_attn.py``) -- there is **no** flash-attention / Triton
  / SDPA kernel, so no ROCm SDPA patch is required. We keep ``num_workers=0``
  (no DataLoader here) and never set ``PYTORCH_HIP_ALLOC_CONF``.
* Torch is imported lazily (numpy-only at module load) so the package stays
  importable from the CPU/scapy assembly env, mirroring ``raw_cnn.py``.

Tokenization of an assembler image
----------------------------------
The assembler stores **IP-layer** bytes (L2 already stripped). ET-BERT's own
fine-tuning preprocessing hexlifies the full Ethernet frame and drops the first
``76`` hex chars (= 38 bytes = 14 B Ethernet + 20 B IPv4 header + 4 B L4 ports)
to avoid memorizing addresses/ports. Because L2 is already gone, we drop the
first ``header_strip_bytes`` (default 24 = 20 B IPv4 + 4 B ports) from each
packet, then emit overlapping hex-bigrams, concatenate packets of a flow into
one sequence, prepend ``[CLS]`` and pad/truncate to ``seq_length`` (128).
"""
from __future__ import annotations

import os
from pathlib import Path

import numpy as np

from .base import NFM

# --- vendored ET-BERT / UER-py locations -----------------------------------
_ETBERT_ROOT = Path(__file__).resolve().parents[3] / "vendor" / "nfm" / "etbert"
_VOCAB_PATH = _ETBERT_ROOT / "models" / "encryptd_vocab.txt"
_CONFIG_PATH = _ETBERT_ROOT / "bert_base_config.json"
_CKPT_PATH = _ETBERT_ROOT / "models" / "checkpoints" / "pretrained_model.bin"

EMB_DIM = 768
SEQ_LENGTH = 128          # tokens fed to BERT, incl. [CLS] (ET-BERT fine-tune default)
MAX_SEQ_LENGTH = 512      # position-embedding table size in the checkpoint
HEADER_STRIP_BYTES = 24   # IPv4 header (20) + L4 ports (4); emulates ET-BERT's [76:]
CLS_TOKEN = "[CLS]"


def _cut_bytes(hexstr: str):
    """Split a hex string into 2-char (1-byte) groups. Mirrors ET-BERT ``cut(.,1)``."""
    return [hexstr[i:i + 2] for i in range(0, len(hexstr), 2)]


def bigram_generation(hexstr: str, max_bigrams: int = SEQ_LENGTH) -> str:
    """ET-BERT overlapping hex-bigram tokens for one packet's hex string.

    Each token is two adjacent bytes (4 hex chars); the window slides by one
    byte. Faithful reimplementation of ET-BERT ``bigram_generation`` (pure
    string ops; no scapy/flowcontainer needed).
    """
    bytes_ = _cut_bytes(hexstr)
    out = []
    n = len(bytes_)
    for i in range(n):
        if i == n - 1:
            break
        if len(out) >= max_bigrams:
            break
        out.append(bytes_[i] + bytes_[i + 1])
    return " ".join(out)


def _make_args():
    """Namespace with the UER hyper-params needed to rebuild the ET-BERT trunk."""
    import json
    from argparse import Namespace

    with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)  # emb_size, hidden_size, feedforward_size, heads_num, layers_num, hidden_act, dropout

    return Namespace(
        # sizes from bert_base_config.json
        emb_size=cfg["emb_size"], hidden_size=cfg["hidden_size"],
        feedforward_size=cfg["feedforward_size"], heads_num=cfg["heads_num"],
        layers_num=cfg["layers_num"], hidden_act=cfg["hidden_act"],
        dropout=cfg["dropout"],
        # ET-BERT / UER defaults (see uer/opts.py)
        embedding="word_pos_seg", encoder="transformer", mask="fully_visible",
        max_seq_length=MAX_SEQ_LENGTH, layernorm_positioning="post",
        feed_forward="dense", layernorm="normal",
        remove_embedding_layernorm=False, remove_attention_scale=False,
        remove_transformer_bias=False, factorized_embedding_parameterization=False,
        parameter_sharing=False, relative_position_embedding=False,
        relative_attention_buckets_num=32,
    )


class _BertTrunk:
    """Lazily-built ``embedding`` + ``encoder`` sub-modules (as an nn.Module).

    Kept as a factory so torch stays a lazy import. Submodule names match the
    UER checkpoint keys (``embedding.*`` / ``encoder.*``) so a plain
    ``load_state_dict(strict=False)`` drops only the ``target.*`` MLM head.
    """

    @staticmethod
    def build(args, vocab_size):
        import sys
        import torch.nn as nn

        if str(_ETBERT_ROOT) not in sys.path:
            sys.path.insert(0, str(_ETBERT_ROOT))
        from uer.layers import str2embedding
        from uer.encoders import str2encoder

        class Trunk(nn.Module):
            def __init__(self):
                super().__init__()
                self.embedding = str2embedding[args.embedding](args, vocab_size)
                self.encoder = str2encoder[args.encoder](args)

            def forward(self, src, seg):
                emb = self.embedding(src, seg)
                return self.encoder(emb, seg)  # [B, seq, hidden]

        return Trunk()


class ETBERTExtractor(NFM):
    """Frozen ET-BERT [CLS] embedding (768-d) over hex-bigram BURST tokens."""

    name = "etbert"
    dim = EMB_DIM

    def __init__(self, seq_length: int = SEQ_LENGTH,
                 header_strip_bytes: int = HEADER_STRIP_BYTES,
                 checkpoint_path: str | os.PathLike | None = None):
        super().__init__()
        self.seq_length = seq_length
        self.header_strip_bytes = header_strip_bytes
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else _CKPT_PATH
        self.random_init = False          # set True if checkpoint is unavailable
        self._tokenizer = None
        self._vocab_size = None

    # -- tokenization -------------------------------------------------------
    def _get_tokenizer(self):
        if self._tokenizer is not None:
            return self._tokenizer
        import sys
        from argparse import Namespace
        if str(_ETBERT_ROOT) not in sys.path:
            sys.path.insert(0, str(_ETBERT_ROOT))
        from uer.utils.tokenizers import BertTokenizer
        targs = Namespace(spm_model_path=None, vocab_path=str(_VOCAB_PATH))
        self._tokenizer = BertTokenizer(targs)
        self._vocab_size = len(self._tokenizer.vocab)
        return self._tokenizer

    def _image_to_ids(self, image_u8: np.ndarray) -> list[int]:
        """One flow image [max_pkts, max_bytes] uint8 -> ET-BERT token ids."""
        tok = self._get_tokenizer()
        tokens: list[str] = []
        budget = self.seq_length - 1  # room for [CLS]
        for row in image_u8:
            if not row.any():
                continue  # empty packet slot (assembler zero-padding)
            b = np.trim_zeros(row, "b")          # drop trailing zero padding
            if b.size <= self.header_strip_bytes:
                continue
            b = b[self.header_strip_bytes:]      # emulate ET-BERT [76:] on IP-layer bytes
            hexstr = b.tobytes().hex()
            bigrams = bigram_generation(hexstr, max_bigrams=budget)
            if bigrams:
                tokens.extend(tok.tokenize(bigrams))
            if len(tokens) >= budget:
                break
        tokens = tokens[:budget]
        ids = tok.convert_tokens_to_ids([CLS_TOKEN] + tokens)
        return ids

    def build_batch(self, images_u8: np.ndarray):
        import torch
        src, seg = [], []
        for image in images_u8:
            ids = self._image_to_ids(np.asarray(image, dtype=np.uint8))
            s = [1] * len(ids)
            # pad to seq_length with [PAD]=0 / seg=0
            while len(ids) < self.seq_length:
                ids.append(0)
                s.append(0)
            src.append(ids[:self.seq_length])
            seg.append(s[:self.seq_length])
        src_t = torch.tensor(src, dtype=torch.long, device=self.device)
        seg_t = torch.tensor(seg, dtype=torch.long, device=self.device)
        return src_t, seg_t

    # -- model --------------------------------------------------------------
    def load(self, device: str = "cuda"):
        import torch
        self.device = device
        self._get_tokenizer()  # sets self._vocab_size

        args = _make_args()
        model = _BertTrunk.build(args, self._vocab_size)

        if self.checkpoint_path.exists():
            # ET-BERT ships a plain UER state_dict (torch.save of OrderedDict[tensor]).
            # torch>=2.6 defaults weights_only=True which is correct here; fall back
            # only if an older-style pickled object is encountered.
            try:
                state = torch.load(str(self.checkpoint_path), map_location="cpu",
                                   weights_only=True)
            except Exception:
                state = torch.load(str(self.checkpoint_path), map_location="cpu",
                                   weights_only=False)
            if isinstance(state, dict) and "model" in state and "embedding.word_embedding.weight" not in state:
                state = state["model"]
            incompatible = model.load_state_dict(state, strict=False)
            # Sanity: every trunk (embedding/encoder) param must have been loaded;
            # only the target.* MLM head may be missing.
            missing_trunk = [k for k in incompatible.missing_keys
                             if k.startswith(("embedding.", "encoder."))]
            assert not missing_trunk, f"ET-BERT trunk keys not loaded: {missing_trunk[:8]}"
            self.checkpoint_hash = _sha256(self.checkpoint_path)
            self.random_init = False
        else:
            # Checkpoint unavailable (e.g. gated Drive link): same-config random init.
            self.random_init = True
            self.checkpoint_hash = None

        self.model = model.to(device)
        return self

    def forward(self, batch):
        src_t, seg_t = batch
        out = self.model(src_t, seg_t)   # [B, seq, hidden]
        return out[:, 0, :]              # [CLS] hidden state -> [B, 768]

    def provenance(self) -> dict:
        p = super().provenance()
        p.update({
            "tokenization": "hex-bigram (2-byte overlapping, 1-byte stride) wordpiece",
            "seq_length": self.seq_length,
            "header_strip_bytes": self.header_strip_bytes,
            "vocab_size": self._vocab_size,
            "random_init": self.random_init,
            "checkpoint": str(self.checkpoint_path) if not self.random_init else None,
        })
        return p


def _sha256(path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
