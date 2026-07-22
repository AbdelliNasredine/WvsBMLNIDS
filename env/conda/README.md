# Black-box (NFM) conda environments — Windows / ROCm

Per-model Python environments for the black-box study. GPU work (tokenize →
embed → fine-tune) runs natively in conda on the ROCm stack; the PCAP flow
assembly and all white-box extractors stay CPU-side (nids-xstudy env / Linux
containers).

## Verified base (plan §5.0)
`rocm721-py312` — Python 3.12, `torch 2.9.1+rocm7.2.1` (repo.radeon.com ROCm 7.2.1
wheels), numpy 1.26.4. Device: **AMD Radeon(TM) 8060S Graphics** (gfx1151),
Adrenalin 26.2.2, Windows 11. Measured FP16 4096³ GEMM ≈ 15.5 TFLOPS.
`torch.cuda.is_available() == True` (ROCm HIP exposed through the `torch.cuda` API).

The base env already exists on the host; `base-rocm721.yml` and
`locks/rocm721-py312.txt` are the committed *records* of it (the ROCm torch wheels
are installed from repo.radeon.com, not conda/PyPI — see comments in the yml).

## Per-model envs
Each model gets an env cloned from the base, then repo requirements installed
**around** torch (never let a repo's requirements.txt replace the ROCm wheels):

```powershell
conda create -n <model> --clone rocm721-py312
# then, inside the env, install repo deps EXCLUDING torch/torchvision/torchaudio
```

`setup_envs.ps1` automates this and sha256-verifies checkpoints.

## Uniform Windows/ROCm constraints (applied to every model for fairness)
- No Triton / flash-attn: patch repos to PyTorch-native `scaled_dot_product_attention`.
- Do **not** set `PYTORCH_HIP_ALLOC_CONF` (crashes on gfx1151).
- Persist the MIOpen kernel cache across runs; warm up once per input shape
  (first-run kernel search is slow — see the 5.9 flows/s smoke artifact).
- DataLoaders: `num_workers` low (Windows spawn).
- Every wrapper asserts `next(model.parameters()).is_cuda` before embedding
  (silent CPU fallback is the #1 failure mode).

Deviations (e.g. ET-BERT needing py3.10 tooling, NetMamba SSM fallback) are
recorded in `../../NFM_CARDS.md`.
