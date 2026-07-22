# Impact of White-Box Feature Extraction on ML-Based NIDS Performance

Empirical study measuring how the choice of network-traffic feature extractor
(NFStream, Zeek, CICFlowMeter original vs. DistriNet-fixed, Argus, Tranalyzer2)
affects measured ML-NIDS performance, holding the raw traffic and ground-truth
labels fixed. 

**Core design principle:** the extractor is the *only* thing that changes between
conditions. All PCAP inputs, labeling logic, splits, preprocessing, models and
metrics are one shared pipeline. Labels are computed from the *traffic* (never
taken from tool-shipped labels) so they are identical across tools.


## Setup

```bash
conda env create -f env/environment.yml
conda activate nids-xstudy
pip install -r env/requirements.txt
```

## Extraction (CICIDS2017)

NFStream runs natively (pure Python). The other extractors run in Docker
(`docker build` each image under `env/docker/` first — see
[env/docker/README.md](env/docker/README.md) for build status).

```bash
python -m nids_xstudy.extraction.run_nfstream \
    --pcap E:/CIC-IDS-2017/PCAPs/Tuesday-WorkingHours.pcap \
    --dataset cicids2017 --capture Tuesday

python scripts/label.py --dataset cicids2017 --tool nfstream --capture Tuesday
```