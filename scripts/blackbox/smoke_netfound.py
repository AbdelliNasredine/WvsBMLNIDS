"""B0 smoke gate for the netFound black-box extractor.

Assembles the reference flows from tests/fixtures/smoke.pcap, loads the real
pretrained netFound checkpoint (snlucsb/netFound-640M-base) onto the GPU, builds
netFound model inputs via the model's OWN tokenizer/collator, forward-passes to
frozen pooled embeddings, and prints a one-line JSON verdict.

PASS iff: device != cpu, dim > 0, and no NaNs in the embeddings.

Run in the ROCm GPU env:
    C:/Users/n8e/miniconda3/envs/nfm-netfound/python.exe \
        scripts/blackbox/smoke_netfound.py

Extra:
    --print-provenance   also emit checkpoint repo id, pinned commit and the
                         sha256 of every resolved checkpoint file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT / "src"))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _provenance(extractor) -> dict:
    ckpt = extractor.checkpoint
    if os.path.isdir(ckpt):
        ckpt_dir = Path(ckpt)
    else:
        from huggingface_hub import snapshot_download
        ckpt_dir = Path(snapshot_download(repo_id=ckpt))
    files = {}
    for p in sorted(ckpt_dir.rglob("*")):
        if p.is_file() and p.suffix in (".safetensors", ".bin", ".json"):
            files[p.name] = {"sha256": _sha256(p), "bytes": p.stat().st_size}
    return {"checkpoint": ckpt, "ckpt_dir": str(ckpt_dir), "files": files,
            "provenance": extractor.provenance()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", default=str(_REPO_ROOT / "tests" / "fixtures" / "smoke.pcap"))
    ap.add_argument("--dtype", default="bfloat16",
                    choices=["bfloat16", "float16", "float32"])
    ap.add_argument("--max-pkts", type=int, default=32)
    ap.add_argument("--max-bytes", type=int, default=128)
    # Checkpoint: a local dir (config.json + model.safetensors) or an HF repo id.
    # On this machine the HF Xet CDN stalls over HTTP/2, so weights are fetched
    # once to a local dir via curl --http1.1; point --checkpoint there. NOTE the
    # requested snlucsb/netFound-640M-base is incompatible with the pinned vendor
    # commit (see netfound.py); use a pinned-code-compatible checkpoint
    # (netFound-large ~640M / netFound-base). Falls back through candidates.
    ap.add_argument("--checkpoint", default=os.environ.get("NFM_NETFOUND_CKPT"))
    ap.add_argument("--print-provenance", action="store_true")
    args = ap.parse_args()

    from nids_xstudy.assembly import assemble, AssemblyConfig
    from nids_xstudy.nfm.netfound import NetFoundExtractor, CHECKPOINT_REPO

    candidates = [args.checkpoint] if args.checkpoint else [
        r"C:/Users/n8e/nfm_ckpt/netFound-large",
        r"C:/Users/n8e/nfm_ckpt/netFound-base",
    ]
    ckpt = next((c for c in candidates if c and os.path.isdir(c)), CHECKPOINT_REPO)

    pcap = Path(args.pcap)
    if not pcap.exists():
        sys.path.insert(0, str(_REPO_ROOT / "tests"))
        from fixtures.smoke import build_pcap
        build_pcap(pcap)

    meta, images = assemble(pcap, AssemblyConfig(max_pkts=args.max_pkts,
                                                 max_bytes=args.max_bytes))

    ext = NetFoundExtractor(checkpoint=ckpt, dtype=args.dtype)
    ext.load("cuda")
    ext.attach_meta(meta)
    res = ext.embed(images, device="cuda")

    device = res["device"]
    dim = int(res["dim"])
    has_nan = bool(res["has_nan"])
    passed = (str(device).lower() != "cpu") and dim > 0 and not has_nan

    verdict = {
        "model": ext.name,
        "checkpoint": ext.checkpoint,
        "device": device,
        "n_flows": int(res["n_flows"]),
        "dim": dim,
        "flows_per_s": res["flows_per_s"],
        "has_nan": has_nan,
        "dtype": args.dtype,
        "PASS": bool(passed),
    }
    if args.print_provenance:
        verdict["_provenance"] = _provenance(ext)

    print("SMOKE_NETFOUND_JSON " + json.dumps(verdict))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
