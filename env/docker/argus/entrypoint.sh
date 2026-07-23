#!/usr/bin/env bash

set -euo pipefail
PCAP="$1"; OUT="$2"; MODE="${3:-bi}"
NAME="$(basename "${PCAP}")"
ARG_OUT="/tmp/${NAME}.argus"
CSV="${OUT}/${NAME}.argus.csv"

argus -r "${PCAP}" -w "${ARG_OUT}"

FIELDS="stime ltime dur proto saddr sport daddr dport spkts dpkts sbytes dbytes state flgs"
if [ "${MODE}" = "uni" ]; then
  # aggregate but keep direction split (no bidirectional merge)
  racluster -r "${ARG_OUT}" -u -n -p 6 -c ',' -M nomerge -s ${FIELDS} > "${CSV}"
else
  racluster -r "${ARG_OUT}" -u -n -p 6 -c ',' -s ${FIELDS} > "${CSV}"
fi
