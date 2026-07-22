#!/usr/bin/env bash
# yaf-run <pcap> <outdir>  ->  <outdir>/<name>.json  (super_mediator NDJSON)
# biflow is yaf's default (no --uniflow, no --silk). The binary IPFIX goes to
# container-local /tmp; only the text NDJSON is written to the mounted /out.
set -euo pipefail
PCAP="$1"; OUT="$2"
NAME="$(basename "${PCAP}")"
IPFIX="/tmp/${NAME}.ipfix"
# YAF's appLabel DPI plugin segfaults on a small number of packets in some
# captures (e.g. DAPT2020 thursday). Set NO_APPLABEL=1 to run without it; the
# flow-level features are identical, only the applicationLabel column is dropped.
APPLABEL_FLAG="--applabel"
if [ "${NO_APPLABEL:-0}" = "1" ]; then APPLABEL_FLAG=""; fi
yaf --in "${PCAP}" --out "${IPFIX}" ${APPLABEL_FLAG} --max-payload 4096
super_mediator --in "${IPFIX}" --out "${OUT}/${NAME}.json" -m JSON
