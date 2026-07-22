#!/usr/bin/env bash
# t2-extract <pcap> <outdir>  ->  <outdir>/<name>_flows.txt
set -euo pipefail
PCAP="$1"; OUT="$2"
NAME="$(basename "${PCAP}")"
T2BIN="$(command -v tranalyzer 2>/dev/null || find /opt /root -name tranalyzer -type f 2>/dev/null | head -1)"
if [ -z "${T2BIN}" ]; then echo "tranalyzer binary not found" >&2; exit 1; fi
"${T2BIN}" -r "${PCAP}" -w "${OUT}/${NAME}_"
