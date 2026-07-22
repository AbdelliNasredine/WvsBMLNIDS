"""netFound black-box foundation-model extractor (frozen embeddings).

netFound (SNL, UC Santa Barbara; arXiv:2310.17025) is a hierarchical multimodal
transformer over network traffic: packets -> bursts -> flows, with a
protocol-aware tokenizer over IP/TCP/UDP/ICMP header fields plus per-burst
metadata (direction, byte count, packet count, inter-arrival time). This wrapper
loads the pretrained ``snlucsb/netFound-640M-base`` checkpoint onto the GPU and
exposes a frozen, pooled encoder embedding (one vector per flow), following the
model's OWN inference path (``src/netFoundInference.py``):

    emb = mean_over_tokens( base_transformer(...).last_hidden_state )

Torch is imported lazily (numpy at top, ``import torch`` inside methods) so this
module can be imported from the CPU (scapy) env, mirroring ``raw_cnn.py``.

Reuse / faithfulness
--------------------
* REUSED verbatim from the pinned vendor repo (no edits to their model code):
  ``modules.netFoundTokenizer.netFoundTokenizer`` (the protocol-aware tokenizer),
  ``modules.netFoundDataCollator.SimpleDataCollator`` (burst padding/flattening),
  ``modules.netFoundModels.netFoundLanguageModelling`` (the model + encoder), and
  the checkpoint's own ``config.json`` (architecture + truncation defaults).
* APPROXIMATED for the B0 smoke gate (full pcap->Arrow pipeline is Phase B1): the
  raw-field extraction that netFound normally does with a C++/tshark binary
  (``pre_process_src/3_extract_fields`` -> ``Tokenize.py``) is reproduced here in
  Python directly from the assembler's IP-layer packet bytes, and burst
  segmentation is approximated by maximal same-direction packet runs (netFound
  splits fwd/bwd sub-streams on inter-arrival gaps). The 16-bit field->token
  quantization, field selection, per-burst metadata, strip-payload handling,
  truncation, and CLS insertion all go through netFound's own tokenizer, so the
  input *schema* is faithful; the field *values* are a documented approximation
  of the C++ extractor. This is sufficient for the B0 gate (device/dim/NaN); a
  byte-exact builder driven by ``pre_process_src`` is the Phase-B1 deliverable.

ROCm / Windows notes
--------------------
* We force ``config.use_flash_attn = False``: netFound only takes its custom
  FlashAttention path when this flag is set; with it False the model uses HF's
  eager ``RoFormerAttention`` (no Triton / no flash-attn kernels), which runs on
  ROCm. No attention monkeypatch is therefore required.
* Default dtype is bfloat16 (what the vendor's own ``netFoundInference.py`` uses
  via ``--bf16``): halves memory for the ~640M-param checkpoint and is
  well-supported on this ROCm stack. Pass ``dtype="float32"`` to override.
* ``PYTORCH_HIP_ALLOC_CONF`` is never set here; dataloader-style workers are not
  used (single-process forward).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import numpy as np

from .base import NFM

# --- checkpoint / vendor provenance (deliverable #3) --------------------------
VENDOR_COMMIT = "b3ab5a3aa72640cc725ef207fb0145b039a57d35"  # vendor/nfm/netfound pin
#
# IMPORTANT (checkpoint <-> code compatibility). The task named
# ``snlucsb/netFound-640M-base``, but that checkpoint is architecturally
# INCOMPATIBLE with the pinned vendor commit b3ab5a3: it predates the repo's
# ModernBert refactor. Concretely, its state_dict has classic-BERT FFN blocks
# (``burst_encoder.intermediate.dense`` / ``.output.dense``), a
# ``seg_embeddings`` table, ``protoEmbedding`` sized [65536,H] and vocab 65539 --
# whereas b3ab5a3 builds GeGLU ``ModernBertMLP`` (``mlp.Wi``/``mlp.Wo``), no
# seg_embeddings, ``protoEmbedding`` [18,H] and vocab 65600. ``from_pretrained``
# therefore fails with shape/key mismatches (verified). Its resolved file sha256
# is recorded below for the record.
#
# The pinned code's OWN published checkpoints -- snlucsb/netFound-{small,base,
# large} -- DO match b3ab5a3 (GeGLU FFN, protoEmbedding [18,H], vocab 65600).
# ``netFound-large`` (hidden 1024, 24 layers ~ 640M params, dim 1024) is the
# drop-in compatible equivalent of the requested 640M model; ``netFound-base``
# (hidden 768, 12 layers, dim 768) is a smaller compatible option that loads
# cleanly and downloads ~4x faster. Default to large for the intended scale.
CHECKPOINT_REPO = "snlucsb/netFound-large"          # pinned-code-compatible ~640M
CHECKPOINT_REPO_REQUESTED = "snlucsb/netFound-640M-base"  # incompatible with b3ab5a3
# Resolved model.safetensors sha256 per deliverable #3 (verified by download):
#   netFound-640M-base : REQUESTED but INCOMPATIBLE with the pin (from_pretrained
#                        errors on FFN/proto/seg shape mismatch). 2,847,390,504 B.
#   netFound-base      : pinned-code-COMPATIBLE; loads cleanly; the B0 smoke ran on
#                        this one (dim 768). 698,780,900 B.
CHECKPOINT_640M_BASE_SHA256 = "5569c7a628a290158bb115e91e1ff2c39e2de6f3646fecc53302856d05696074"
CHECKPOINT_BASE_SHA256      = "e6237f49ce58840f8bf7d0cafa5ae80f58d05ea158053d031792d0369d7f5105"
# sha256 of the checkpoint actually loaded is computed lazily in provenance();
# recompute any file with smoke_netfound.py --print-provenance.
CHECKPOINT_SHA256 = None

# Repo root: .../src/nids_xstudy/nfm/netfound.py -> parents[3]
_REPO_ROOT = Path(__file__).resolve().parents[3]
_VENDOR_SRC = _REPO_ROOT / "vendor" / "nfm" / "netfound" / "src"

# netFound tokenizer constants (see pre_process_src/Tokenize.py, netFoundTokenizer)
_TOKEN_BYTES = 2            # every field token is a 16-bit big-endian slice
_PAYLOAD_TOKENS = 6        # 12 payload bytes -> 6 tokens ("Payload" field)
_FLOW_SIZE_LIMIT = 12      # netFound FLOW_SIZE_LIMIT (max bursts kept)
_BURST_SIZE_LIMIT = 6      # netFound BURST_SIZE_LIMIT (max packets/burst)

# Per-protocol header field layout (DefaultConfigNoTCPOptions.json). Each entry is
# (extractor_fn_key, number_of_16bit_tokens). Header token counts match
# netFoundTokenizer.PROTOCOLS_LENGTH_WITHOUT_PAYLOAD: TCP=12, UDP=6, ICMP=7.
_IP_FIELDS = [("IP_hl", 1), ("IP_tos", 1), ("IP_tl", 1), ("IP_Flags", 1), ("IP_ttl", 1)]
_L4_FIELDS = {
    6:  [("TCP_Flags", 1), ("TCP_wsize", 1), ("TCP_seq", 2), ("TCP_ackn", 2), ("TCP_urp", 1)],
    17: [("UDP_len", 1)],
    1:  [("ICMP_type", 1), ("ICMP_code", 1)],
}
_HEADER_TOKENS = {6: 12, 17: 6, 1: 7}
_SUPPORTED_PROTOS = (1, 6, 17)


def _int_to_tokens(value: int, n_tokens: int) -> list[int]:
    """Reproduce netFound's field->token quantization: value -> big-endian bytes
    (n_tokens*2 bytes) -> list of n_tokens unsigned 16-bit ints."""
    value = int(value) & ((1 << (16 * n_tokens)) - 1)
    raw = value.to_bytes(n_tokens * _TOKEN_BYTES, byteorder="big")
    return [int.from_bytes(raw[i:i + _TOKEN_BYTES], "big")
            for i in range(0, len(raw), _TOKEN_BYTES)]


def _parse_ip_packet(ip_bytes: np.ndarray) -> dict | None:
    """Extract the header fields netFound tokenizes, directly from IP-layer bytes.

    Approximates pre_process_src/3_extract_fields (C++/tshark). Returns None for
    non-IPv4 / malformed packets. Sequence/ack numbers are absolute here (netFound
    uses tshark relative numbers) -- a documented value-level approximation.
    """
    b = bytes(ip_bytes)
    if len(b) < 20 or (b[0] >> 4) != 4:
        return None
    ihl_words = b[0] & 0x0F
    ihl_bytes = ihl_words * 4
    if ihl_bytes < 20 or len(b) < ihl_bytes:
        return None
    proto = b[9]
    f = {
        "proto": proto,
        "IP_hl": ihl_bytes,                       # header length in bytes (README)
        "IP_tos": b[1],
        "IP_tl": int.from_bytes(b[2:4], "big"),
        "IP_Flags": b[6] >> 5,                     # top 3 bits of byte 6
        "IP_ttl": b[8],
    }
    off = ihl_bytes
    if proto == 6 and len(b) >= off + 20:          # TCP
        data_off = (b[off + 12] >> 4) * 4
        f.update({
            "TCP_Flags": b[off + 13],
            "TCP_wsize": int.from_bytes(b[off + 14:off + 16], "big"),
            "TCP_seq": int.from_bytes(b[off + 4:off + 8], "big"),
            "TCP_ackn": int.from_bytes(b[off + 8:off + 12], "big"),
            "TCP_urp": int.from_bytes(b[off + 18:off + 20], "big"),
        })
        payload_off = off + max(data_off, 20)
    elif proto == 17 and len(b) >= off + 8:        # UDP
        f["UDP_len"] = int.from_bytes(b[off + 4:off + 6], "big")
        payload_off = off + 8
    elif proto == 1 and len(b) >= off + 4:         # ICMP
        f["ICMP_type"] = b[off]
        f["ICMP_code"] = b[off + 1]
        payload_off = off + 8
    else:
        # Unsupported / truncated L4: keep IP fields, zero the L4 fields below.
        payload_off = len(b)
    f["_payload"] = b[payload_off:payload_off + _PAYLOAD_TOKENS * _TOKEN_BYTES]
    return f


def _packet_tokens(fields: dict, proto: int, include_payload: bool) -> list[int]:
    """Build the flat token list for one packet in netFound field order.

    Header layout follows the flow's protocol. When ``include_payload`` (i.e. the
    checkpoint config has strip_payload=True), 6 payload tokens are appended so
    netFoundTokenizer._strip_payload finds header+payload blocks and strips them.
    """
    toks: list[int] = []
    for name, nt in _IP_FIELDS:
        toks += _int_to_tokens(fields.get(name, 0), nt)
    for name, nt in _L4_FIELDS.get(proto, _L4_FIELDS[6]):
        toks += _int_to_tokens(fields.get(name, 0), nt)
    if include_payload:
        pay = fields.get("_payload", b"")
        pay = pay + b"\x00" * (_PAYLOAD_TOKENS * _TOKEN_BYTES - len(pay))
        toks += [int.from_bytes(pay[i:i + _TOKEN_BYTES], "big")
                 for i in range(0, _PAYLOAD_TOKENS * _TOKEN_BYTES, _TOKEN_BYTES)]
    return toks


class NetFoundExtractor(NFM):
    """Frozen netFound encoder -> pooled per-flow embedding (loads real checkpoint
    onto the GPU). Reuses netFound's own tokenizer, collator and model classes."""

    name = "netfound"
    dim = None                       # set from checkpoint config.hidden_size at load
    checkpoint_hash = CHECKPOINT_SHA256

    def __init__(self, checkpoint: str | None = None, dtype: str = "bfloat16",
                 max_bursts: int | None = None, max_pkts_per_burst: int | None = None):
        super().__init__()
        self.checkpoint = checkpoint or CHECKPOINT_REPO
        self.dtype_str = dtype
        self.config = None
        self.tokenizer = None
        self._collator = None
        self._include_payload = True
        self._max_bursts = max_bursts
        self._max_pkts_per_burst = max_pkts_per_burst
        # Optional richer inputs attached by the caller (per-flow assembler meta).
        self._examples = None        # list[dict] in netFound Arrow schema, flow-aligned
        self._cursor = 0

    # -- loading ---------------------------------------------------------------
    def _ensure_vendor_on_path(self):
        p = str(_VENDOR_SRC)
        if p not in sys.path:
            sys.path.insert(0, p)

    def _resolve_checkpoint_dir(self) -> str:
        if os.path.isdir(self.checkpoint):
            return self.checkpoint
        from huggingface_hub import snapshot_download
        return snapshot_download(repo_id=self.checkpoint)

    def load(self, device: str = "cuda"):
        import torch
        self._ensure_vendor_on_path()
        from modules.netFoundConfigBase import netFoundConfig
        from modules.netFoundModels import netFoundLanguageModelling
        from modules.netFoundTokenizer import netFoundTokenizer
        from modules.netFoundDataCollator import SimpleDataCollator

        ckpt_dir = self._resolve_checkpoint_dir()

        # Architecture + truncation defaults come from the checkpoint's own config.
        config = netFoundConfig.from_pretrained(ckpt_dir)
        config.pretraining = False        # frozen encoder use (matches inference)
        config.use_flash_attn = False     # ROCm: force eager attention (no flash/Triton)
        self.config = config
        self.dim = int(config.hidden_size)
        # netFound's Arrow format always stores header+payload tokens; the tokenizer
        # strips the payload only when config.strip_payload is set. The 640M-base
        # checkpoint keeps payload (strip_payload=False, max_burst_length=109=6*18+1).
        self._include_payload = True
        self._strip_payload = bool(getattr(config, "strip_payload", False))

        dtype = {"bfloat16": torch.bfloat16, "float16": torch.float16,
                 "float32": torch.float32}[self.dtype_str]
        self.torch_dtype = dtype

        model = netFoundLanguageModelling.from_pretrained(ckpt_dir, config=config)
        model.to(device=device, dtype=dtype)
        model.eval()
        self.model = model
        self.device = device

        # record provenance for the resolved checkpoint (known SHAs; no re-hash)
        tag = str(ckpt_dir).replace("\\", "/").rstrip("/").split("/")[-1].lower()
        self.checkpoint_hash = {
            "netfound-base": CHECKPOINT_BASE_SHA256,
            "netfound-640m-base": CHECKPOINT_640M_BASE_SHA256,
        }.get(tag)

        # netFound's own tokenizer + collator (unmodified vendor code).
        tok = netFoundTokenizer(config=config)
        tok.pretraining = True            # inference sets this; skips label handling
        tok.raw_labels = False
        self.tokenizer = tok
        self._collator = SimpleDataCollator(pad_token_id=tok.pad_token_id)

        # burst/packet caps so that a burst's post-tokenizer token count never
        # exceeds max_burst_length-1 (keeps the fixed-geometry reshape valid).
        # Effective tokens/packet = header (+payload if not stripped). Use the
        # largest protocol header (TCP) as the bound.
        tpp = _HEADER_TOKENS[6] + (0 if self._strip_payload else _PAYLOAD_TOKENS)
        self._max_bursts = self._max_bursts or min(_FLOW_SIZE_LIMIT, int(config.max_bursts))
        self._max_pkts_per_burst = self._max_pkts_per_burst or min(
            _BURST_SIZE_LIMIT, max(1, (int(config.max_burst_length) - 1) // tpp))
        return self

    # -- input building --------------------------------------------------------
    def attach_meta(self, meta) -> "NetFoundExtractor":
        """Attach the assembler's per-flow meta DataFrame so build_batch can use
        real direction / burst structure. Flow order must match the image array.
        Call before embed(); resets the internal cursor."""
        self._pending_meta = meta.reset_index(drop=True)
        self._cursor = 0
        # examples are built lazily per image-slice in build_batch (keeps memory low)
        self._examples = "meta"
        return self

    def _cap_tokens_per_packet(self, proto: int) -> int:
        return _HEADER_TOKENS.get(proto, 12) + (_PAYLOAD_TOKENS if self._include_payload else 0)

    def _flow_example_from_packets(self, packets: list[dict], dirs, times, proto: int) -> dict:
        """Assemble one netFound Arrow-schema example from parsed packets.

        packets[i]: parsed header dict for packet i (or None -> zero packet).
        dirs[i]: 0=fwd/1=bwd (assembler) or None. times[i]: seconds from flow start.
        Bursts = maximal same-direction runs (approx of netFound's fwd/bwd IAT
        split), capped to max_pkts_per_burst packets and max_bursts bursts.
        """
        n = len(packets)
        if dirs is None:
            dirs = [0] * n
        # group into maximal same-direction runs
        bursts_idx: list[list[int]] = []
        cur: list[int] = []
        cur_dir = None
        for i in range(n):
            d = dirs[i] if i < len(dirs) else 0
            if cur and (d != cur_dir or len(cur) >= self._max_pkts_per_burst):
                bursts_idx.append(cur)
                cur = []
            cur.append(i)
            cur_dir = d
        if cur:
            bursts_idx.append(cur)
        bursts_idx = bursts_idx[:self._max_bursts]

        burst_tokens, directions, byte_ls, count_ls, iat_ls = [], [], [], [], []
        prev_first_t = None
        for grp in bursts_idx:
            toks: list[int] = []
            tl_sum = 0
            for i in grp:
                pf = packets[i]
                if pf is None:
                    toks += [0] * self._cap_tokens_per_packet(proto)
                    continue
                toks += _packet_tokens(pf, proto, self._include_payload)
                tl_sum += int(pf.get("IP_tl", 0))
            burst_tokens.append(toks)
            d0 = dirs[grp[0]] if grp[0] < len(dirs) else 0
            directions.append(bool(d0 == 0))          # True = fwd/initiator
            byte_ls.append(int(tl_sum))
            count_ls.append(int(len(grp)))
            t0 = float(times[grp[0]]) if (times is not None and grp[0] < len(times)) else 0.0
            iat_ms = 0 if prev_first_t is None else max(0, int(round((t0 - prev_first_t) * 1000)))
            iat_ls.append(iat_ms)
            prev_first_t = t0
        flow_dur = int(round(float(times[-1]) * 1000)) if (times is not None and len(times)) else 0
        return {
            "burst_tokens": burst_tokens,
            "directions": directions,
            "bytes": byte_ls,
            "counts": count_ls,
            "iats": iat_ls,
            "protocol": int(proto),
            "flow_duration": int(flow_dur),
        }

    def _examples_from_images_meta(self, images_u8: np.ndarray, meta_rows) -> list[dict]:
        out = []
        for j in range(len(images_u8)):
            img = images_u8[j]
            if meta_rows is not None:
                row = meta_rows.iloc[j]
                dirs = list(row["dirs"]) if row.get("dirs") is not None else None
                times = list(row["times"]) if row.get("times") is not None else None
                proto = int(row["proto"])
                seq_len = int(row["seq_len"]) if "seq_len" in row else len(dirs or [])
            else:
                dirs = times = None
                # count non-empty packet rows (IPv4 version nibble present)
                seq_len = int(np.count_nonzero(img[:, 0] != 0)) or img.shape[0]
                proto = 0
            packets = []
            first_proto = None
            for i in range(min(seq_len, img.shape[0])):
                pf = _parse_ip_packet(img[i])
                packets.append(pf)
                if pf is not None and first_proto is None:
                    first_proto = pf["proto"]
            if proto not in _SUPPORTED_PROTOS:
                proto = first_proto if first_proto in _SUPPORTED_PROTOS else 6
            if not packets:
                packets = [None]
            out.append(self._flow_example_from_packets(packets, dirs, times, proto))
        return out

    def build_batch(self, images_u8: np.ndarray):
        """Turn an image slice into netFound model inputs on self.device, reusing
        netFound's tokenizer + SimpleDataCollator. Uses attached assembler meta
        (real direction/bursts) when available, else derives from image bytes."""
        import torch
        b = len(images_u8)
        meta_rows = None
        if getattr(self, "_examples", None) == "meta" and getattr(self, "_pending_meta", None) is not None:
            meta_rows = self._pending_meta.iloc[self._cursor:self._cursor + b]
            self._cursor += b
        examples = self._examples_from_images_meta(images_u8, meta_rows)

        # Run netFound's own tokenizer (batched dict of per-flow lists), then split
        # into per-example dicts for their collator (mirrors dataset.map + collate).
        batch_in = {k: [ex[k] for ex in examples] for k in examples[0]}
        tok_out = self.tokenizer.tokenize(dict(batch_in))
        per_example = [{k: tok_out[k][i] for k in tok_out} for i in range(b)]
        collated = self._collator(per_example)
        return self._to_fixed_geometry(collated)

    def _to_fixed_geometry(self, collated):
        """Re-pad the collator's dynamic (num_bursts x burst_len) layout to the
        checkpoint's fixed (max_bursts x max_burst_length) geometry and move to GPU.

        Required by the non-RoFormer (Roberta) embedding path: it recomputes
        position ids by tiling a length-``max_position_embeddings`` buffer, which
        is only well-defined when the flattened sequence length is an exact
        multiple of ``max_burst_length``. Pad tokens get attention_mask=0, so the
        extra positions/bursts are ignored (a fully-masked burst yields uniform,
        finite attention -- no NaNs). ``dataset_burst_sizes`` is set so the model's
        derived ``batch_max_burst_length`` equals ``max_burst_length``.
        """
        import torch
        dev, dt = self.device, self.torch_dtype
        mbl = int(self.config.max_burst_length)
        mb = int(self.config.max_bursts)
        pad_id = int(self.tokenizer.pad_token_id)

        B = collated["input_ids"].shape[0]
        bmbl_dyn = int(collated["dataset_burst_sizes"].max().item()) + 1
        L = collated["input_ids"].shape[1]
        nb_dyn = L // bmbl_dyn

        def repad(name, pad_val, dtype):
            x = collated[name].reshape(B, nb_dyn, bmbl_dyn)
            out = x.new_full((B, mb, mbl), pad_val)
            out[:, :min(nb_dyn, mb), :min(bmbl_dyn, mbl)] = \
                x[:, :min(nb_dyn, mb), :min(bmbl_dyn, mbl)]
            return out.reshape(B, mb * mbl).to(dev, dtype=dtype)

        dbs = torch.zeros(B, mb, dtype=torch.long, device=dev)
        dbs[:, 0] = mbl - 1   # force batch_max_burst_length == max_burst_length
        return {
            "input_ids": repad("input_ids", pad_id, torch.long),
            "attention_mask": repad("attention_mask", 0, torch.long),
            "direction": repad("direction", 0, dt),
            "iats": repad("iats", 0, dt),
            "bytes": repad("bytes", 0, dt),
            "pkt_count": repad("pkt_count", 0, dt),
            "protocol": collated["protocol"].to(dev),
            "dataset_burst_sizes": dbs,
        }

    def forward(self, batch):
        """Frozen pooled embedding = mean over encoder token hidden states
        (netFoundInference.encode_batch). Returns [B, hidden_size]."""
        import torch
        bt = self.model.base_transformer
        bsz, seq_len = batch["input_ids"].shape
        position_ids = torch.arange(seq_len, device=self.device).unsqueeze(0).expand(bsz, -1)
        out = bt(
            input_ids=batch["input_ids"],
            attention_mask=batch["attention_mask"],
            position_ids=position_ids,
            direction=batch["direction"],
            iats=batch["iats"],
            bytes=batch["bytes"],
            pkt_count=batch["pkt_count"],
            protocol=batch["protocol"],
            dataset_burst_sizes=batch["dataset_burst_sizes"],
            return_dict=True,
        ).last_hidden_state
        return out.mean(dim=1)

    def provenance(self) -> dict:
        d = super().provenance()
        d.update({
            "checkpoint_repo": self.checkpoint,
            "vendor_commit": VENDOR_COMMIT,
            "dtype": self.dtype_str,
            "input_builder": "B0 approximation (netFound tokenizer+collator reused; "
                             "field extraction from IP bytes; burst=same-dir runs)",
        })
        if self.config is not None:
            d.update({"max_bursts": int(self.config.max_bursts),
                      "max_burst_length": int(self.config.max_burst_length),
                      "strip_payload": bool(getattr(self.config, "strip_payload", True))})
        return d
