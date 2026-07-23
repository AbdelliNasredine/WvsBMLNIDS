# Black-box (NFM) conda environments — Windows / ROCm

Per-model Python environments for the black-box study. GPU work (tokenize →
embed → fine-tune) runs natively in conda on the ROCm stack. the PCAP flow
assembly and all white-box extractors stay CPU-side (nids-xstudy env / Linux
containers).

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
- Persist the MIOpen kernel cache across runs and warm up once per input shape
- DataLoaders: `num_workers` low.
- Every wrapper asserts `next(model.parameters()).is_cuda` before embedding.
