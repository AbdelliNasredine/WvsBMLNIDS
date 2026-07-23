#!/usr/bin/env bash

set -euo pipefail
PCAP="$1"; OUT="$2"
NAME="$(basename "${PCAP}")"
IPFIX="/tmp/${NAME}.ipfix"
APPLABEL_FLAG="--applabel"
if [ "${NO_APPLABEL:-0}" = "1" ]; then APPLABEL_FLAG=""; fi
yaf --in "${PCAP}" --out "${IPFIX}" ${APPLABEL_FLAG} --max-payload 4096
super_mediator --in "${IPFIX}" --out "${OUT}/${NAME}.json" -m JSON
