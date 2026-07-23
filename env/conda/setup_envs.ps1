param(
    [string]$Model = "",
    [switch]$All,
    [string]$Base = "rocm721-py312",
    [string]$RepoRoot = "$PSScriptRoot\..\..\vendor\nfm"
)

$MODELS = @{
    "netfound" = @{ repo = "https://github.com/SNL-UCSB/netFound"; commit = "";
                    env_py = "3.12"; checkpoint = "snlucsb/netFound-640M-base"; sha256 = "" }
    "etbert"   = @{ repo = "https://github.com/linwhitehat/ET-BERT"; commit = "";
                    env_py = "3.10"; checkpoint = ""; sha256 = "" }
    "yatc"     = @{ repo = "https://github.com/NSSL-SJTU/YaTC"; commit = "";
                    env_py = "3.12"; checkpoint = ""; sha256 = "" }
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
    Write-Host "  NEXT (manual, per NFM_CARDS): inspect requirements, install around torch."
    if ($m.sha256) { Write-Host "  verify checkpoint sha256 == $($m.sha256)" }
}

if ($All) { $MODELS.Keys | ForEach-Object { Setup-Model $_ } }
elseif ($Model) { Setup-Model $Model }
else { Write-Host "specify -Model <name> or -All. Models: $($MODELS.Keys -join ', ')" }
