# Extractor Docker images

One image per feature extractor. NFStream is NOT here — it runs natively
(pure Python, `env/requirements.txt`).

Build all (Docker Desktop must be running):

```bash
docker build -t nids-xstudy/zeek:6.0.0                 env/docker/zeek
docker build -t nids-xstudy/cicflowmeter-orig:v4       env/docker/cicflowmeter-orig   --build-arg CFM_REF=<sha>
docker build -t nids-xstudy/cicflowmeter-fixed:distrinet env/docker/cicflowmeter-fixed --build-arg CFM_REF=<sha>
docker build -t nids-xstudy/argus:latest               env/docker/argus
docker build -t nids-xstudy/tranalyzer:0.9.2           env/docker/tranalyzer          --build-arg T2_VERSION=0.9.2
```

## Build / validation status

These images were authored while the Docker daemon was unavailable, so they are
**not yet build-verified**. Before the real extraction runs:

| Image | Confidence | To verify |
|---|---|---|
| zeek | high (official base image) | `flowfeatures.zeek` tcp_packet flag counts fire on Zeek 6 |
| cicflowmeter-orig | medium | gradle task name + jnetpcap native lib path; CLI class + args; timestamp TZ |
| cicflowmeter-fixed | medium | same as orig; confirm fork builds identically |
| argus | medium-high | `ra` field list + `-u` epoch time output |
| tranalyzer | low | tarball URL/version; autogen plugin set; `_flows.txt` column names |

**Reproducibility:** pin `CFM_REF` (commit SHA) and `T2_VERSION` before real runs
so images are exactly reproducible (plan §11 version validity).

## Smoke-testing an image

```bash
python -m nids_xstudy.extraction.run_zeek \
    --pcap tests/fixtures/smoke.pcap --dataset smoke --capture smoke
# then compare against tests/fixtures/smoke.py GROUND_TRUTH
```
Per-tool smoke assertions mirror the NFStream ones (see
`tests/test_nfstream_smoke.py`); a shared cross-tool smoke test is a Phase-0
follow-up once images build.
