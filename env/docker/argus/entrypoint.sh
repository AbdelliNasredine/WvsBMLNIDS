#!/usr/bin/env bash
# argus-extract <pcap> <outdir> [directionality]
# Produces a comma-separated flow CSV at <outdir>/<name>.argus.csv with epoch
# times. racluster aggregates argus' periodic status records (INT/CON/FIN) into
# one final record per flow with correct packet/byte totals. Bidirectional
# biflows by default; "uni" splits into unidirectional records.
set -euo pipefail
PCAP="$1"; OUT="$2"; MODE="${3:-bi}"
NAME="$(basename "${PCAP}")"
# Write argus' BINARY output to container-local /tmp (writing it to a Windows
# bind mount corrupts the file -> racluster then emits unmerged INT+final
# records). Only the final CSV goes to the mounted /out.
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
