#!/usr/bin/env bash

set -euo pipefail
PCAP="$1"; OUT="$2"
NAME="$(basename "${PCAP}")"
/opt/joy/bin/joy bidir=1 dist=1 num_pkts=200 "${PCAP}" > "${OUT}/${NAME}.json.gz"
