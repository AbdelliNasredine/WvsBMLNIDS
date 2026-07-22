<#
setup_envs.ps1 — create per-model conda envs (cloned from the verified base),
clone official repos at pinned commits, install their deps AROUND the ROCm torch
wheels, and sha256-verify checkpoints. Windows PowerShell.

Usage:
    .\setup_envs.ps1 -Model netfound        # one model
    .\setup_envs.ps1 -All                    # every model

Per-model commit/checkpoint/sha256 are pinned in the $MODELS table below as each
model is integrated (Phase B0.4). Records go to ../../NFM_CARDS.md.
#>
param(
    [string]$Model = "",
    [switch]$All,
    [string]$Base = "rocm721-py312",
    [string]$RepoRoot = "$PSScriptRoot\..\..\vendor\nfm"
)

# name -> @{ repo; commit; env_py; checkpoint_url; sha256 }  (pin as integrated)
$MODELS = @{
    "netfound" = @{ repo = "https://github.com/SNL-UCSB/netFound"; commit = "";
                    env_py = "3.12"; checkpoint = "snlucsb/netFound-640M-base"; sha256 = "" }
    "etbert"   = @{ repo = "https://github.com/linwhitehat/ET-BERT"; commit = "";
                    env_py = "3.10"; checkpoint = ""; sha256 = "" }
    "yatc"     = @{ repo = "https://github.com/NSSL-SJTU/YaTC"; commit = "";
                    env_py = "3.12"; checkpoint = ""; sha256 = "" }
    # NetMamba dropped: ROCm-incompatible Mamba kernels (see NFM_CARDS.md).
    # nPrint was removed from the study (see NFM_CARDS.md).
}

function Setup-Model($name) {
    $m = $MODELS[$name]
    if (-not $m) { Write-Error "unknown model $name"; return }
    $env = "nfm-$name"
    Write-Host "=== $name -> env $env ==="
    conda env list | Select-String "^$env\s" | ForEach-Object { Write-Host "  env exists" }
    if (-not (conda env list | Select-String "^$env\s")) {
        conda create -n $env --clone $Base -y
    }
    New-Item -ItemType Directory -Force -Path $RepoRoot | Out-Null
    $dst = Join-Path $RepoRoot $name
    if (-not (Test-Path $dst)) { git clone $m.repo $dst }
    if ($m.commit) { git -C $dst checkout $m.commit }
    Write-Host "  repo at $dst (commit '$($m.commit)')"
    # install repo deps EXCLUDING torch/torchvision/torchaudio (protect ROCm wheels)
    Write-Host "  NEXT (manual, per NFM_CARDS): inspect requirements, install around torch."
    if ($m.sha256) { Write-Host "  verify checkpoint sha256 == $($m.sha256)" }
}

if ($All) { $MODELS.Keys | ForEach-Object { Setup-Model $_ } }
elseif ($Model) { Setup-Model $Model }
else { Write-Host "specify -Model <name> or -All. Models: $($MODELS.Keys -join ', ')" }
