# Extractor Docker images (v2 tool matrix)

One image per feature extractor. NFStream is NOT here — it runs natively
(pure Python, `env/requirements.txt`). Pinned build recipes + parser field maps:
[BUILD_RECIPES.md](BUILD_RECIPES.md).

Build all (Docker Desktop must be running):

```bash
docker build -t nids-xstudy/zeek:6.0.0                    env/docker/zeek
docker build -t nids-xstudy/cicflowmeter-orig:v4          env/docker/cicflowmeter-orig
docker build -t nids-xstudy/cicflowmeter-fixed:distrinet  env/docker/cicflowmeter-fixed
docker build -t nids-xstudy/argus:5                       env/docker/argus
env/docker/tranalyzer/fetch_tarball.sh   # one-time (slow server)
docker build -t nids-xstudy/tranalyzer:0.9.4             env/docker/tranalyzer
docker build -t nids-xstudy/go-flows:9f5628c             env/docker/go-flows
docker build -t nids-xstudy/yaf:2.19.3                   env/docker/yaf
docker build -t nids-xstudy/joy:4.4.1                    env/docker/joy
docker build -t nids-xstudy/nprobe:demo                  env/docker/nprobe
```

## Status (smoke-PCAP validated)

| # | Image | Status | Notes |
|---|---|---|---|
| — | nfstream (native) | ✅ validated | per-direction flags; idle/active timeout configurable |
| 1 | cicflowmeter-orig | ✅ validated | jnetpcap r1425; exhibits the "TCP appendix" split (RQ4) |
| 1 | cicflowmeter-fixed | ✅ validated | Engelen fork; appendix eliminated, +scan flows (RQ4 delta) |
| 3 | nfstream | ✅ validated | (see above) |
| 4 | tranalyzer | ✅ validated | 0.9.4 meson; drops duplicate 'B' reverse records |
| 5 | zeek | ✅ validated | custom flag-counting script; real 5-day extraction done |
| 6 | argus | ✅ validated | **5.0.3 from openargus source** (3.0.8.2 pkg was broken) |
| 7 | flowtbag | ⛔ build-blocked | 2015 gopcap cgo vs modern Go; no start-time. Deferred (optional) |
| 8 | joy | ✅ validated | 20.04 base; 15 derived stats from packet sequences |
| 9 | go-flows | ✅ validated | merged counts only (no per-direction); spec in specs/go-flows |
| 10 | nprobe | ⛔ needs license | image+runner+template ready; nProbe won't run in-container without an ntop license file (set `NIDS_NPROBE_LICENSE`). Demo also caps 25k flows |
| 11 | yaf | ✅ validated | libfixbuf 2.5.4 + yaf 2.19.3 + super_mediator 1.13.2 |

**Reproducibility:** pin `CFM_REF`/`ARGUS_REF`/`CLIENTS_REF`/`NTL_REF` to commit
SHAs before the real runs (currently default branches — see BUILD_RECIPES.md pins).

## Smoke-testing

`pytest tests/test_docker_extractors.py` runs every built image on the synthetic
PCAP and asserts a schema-valid canonical frame + correct HTTP flow (skips any
tool whose image is absent). Tool-specific assertions: `tests/test_zeek_smoke.py`,
`test_tranalyzer_smoke.py`.
