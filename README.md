# Impact of White-Box Feature Extraction on ML-Based NIDS Performance

Empirical study measuring how the choice of network-traffic feature extractor
(NFStream, Zeek, CICFlowMeter original vs. DistriNet-fixed, Argus, Tranalyzer2)
affects measured ML-NIDS performance, holding the raw traffic and ground-truth
labels fixed. See [`plan.md`](plan.md) for the full experimental design.

**Core design principle:** the extractor is the *only* thing that changes between
conditions. All PCAP inputs, labeling logic, splits, preprocessing, models and
metrics are one shared pipeline. Labels are computed from the *traffic* (never
taken from tool-shipped labels) so they are identical across tools.

## Layout

```
env/            pinned Python env + one Dockerfile per extractor
src/nids_xstudy/
  canonical.py      the single flow-schema contract (one row per flow)
  config.py         path resolution (configs/paths.yaml + env overrides)
  extraction/       per-tool runners: PCAP -> canonical parquet
  labeling/         shared traffic-level ground-truth labeling engine
data/labels/        human-authored, versioned attack rules (rules.yaml)
tests/              smoke fixture + unit tests (schema, NFStream, labeling)
configs/            paths + experiment configs
results/            metrics (JSON) + tables + figures
scripts/            orchestration entrypoints
```

Big intermediate artifacts (raw tool output + canonical parquet) are written
off-repo under `data_root` (default `E:/CIC-IDS-2017/study_outputs`); only small
authored inputs and code are versioned.

## Setup

```bash
conda env create -f env/environment.yml
conda activate nids-xstudy
pip install -r env/requirements.txt
pytest -m smoke          # NFStream + labeling smoke tests on the synthetic PCAP
```

## Extraction (CICIDS2017)

NFStream runs natively (pure Python). The other extractors run in Docker
(`docker build` each image under `env/docker/` first — see
[env/docker/README.md](env/docker/README.md) for build status).

```bash
# NFStream, one capture day
python -m nids_xstudy.extraction.run_nfstream \
    --pcap E:/CIC-IDS-2017/PCAPs/Tuesday-WorkingHours.pcap \
    --dataset cicids2017 --capture Tuesday

# Label + class-distribution report for a canonical parquet
python scripts/label.py --dataset cicids2017 --tool nfstream --capture Tuesday
```

## Status

| Phase | State |
|---|---|
| 0 — env + canonical schema + smoke fixture + NFStream runner | **done** |
| 0 — Docker extractors (Zeek / CICFlowMeter / Argus / Tranalyzer) | scaffolded; images need building + validation (Docker was down at authoring) |
| 1 — CICIDS2017 corrected labeling rules + engine | **done** (rules from Liu/Engelen CNS2022 + WTMC2021) |
| 1 — full extraction runs | pending compute |
| 2–5 — divergence, ML grid, ablations, stats | not started |

See the task list / `plan.md` §10 for the execution queue.
