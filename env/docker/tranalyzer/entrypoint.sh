#!/usr/bin/env bash
# t2-extract <pcap> <outdir>  ->  <outdir>/<name>_flows.txt
set -euo pipefail
PCAP="$1"; OUT="$2"
NAME="$(basename "${PCAP}")"
# locate the built tranalyzer binary
T2BIN="$(command -v tranalyzer || echo /root/.local/tranalyzer2/tranalyzer)"
"${T2BIN}" -r "${PCAP}" -w "${OUT}/${NAME}"
