#!/usr/bin/env bash
# argus-extract <pcap> <outdir> [directionality]
# Produces a comma-separated flow CSV at <outdir>/<name>.argus.csv with epoch
# times. Directionality defaults to bidirectional biflows; pass "uni" for the
# unidirectional ablation (RQ / Phase-4 directionality ablation).
set -euo pipefail
PCAP="$1"; OUT="$2"; MODE="${3:-bi}"
NAME="$(basename "${PCAP}")"
ARG_OUT="${OUT}/${NAME}.argus"
CSV="${OUT}/${NAME}.argus.csv"

# -A: keep response data (bidirectional accounting).
argus -r "${PCAP}" -w "${ARG_OUT}"

RA_FLAGS=(-r "${ARG_OUT}" -u -n -p 6 -c ',')
if [ "${MODE}" = "uni" ]; then
  # split biflows into unidirectional records
  RA_FLAGS+=(-M dsrs=-suser -M nodiff)
fi
# header row then data
FIELDS="stime,ltime,dur,proto,saddr,sport,daddr,dport,spkts,dpkts,sbytes,dbytes,state,flgs"
echo "${FIELDS}" > "${CSV}"
ra "${RA_FLAGS[@]}" -s stime ltime dur proto saddr sport daddr dport spkts dpkts sbytes dbytes state flgs >> "${CSV}"
