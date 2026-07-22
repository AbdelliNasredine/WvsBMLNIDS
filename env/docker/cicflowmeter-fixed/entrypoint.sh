#!/usr/bin/env bash
# Run CICFlowMeter's command-line flow generator on a pcap.
#   cfm <pcap> <outdir>
set -euo pipefail
PCAP="$1"; OUT="$2"
cd /opt/CICFlowMeter

JNETPCAP_DIR="$(dirname "$(find . -name 'libjnetpcap.so' | head -n1)")"
JAR="$(find build -name '*.jar' | grep -viE 'sources|javadoc' | head -n1)"
CP="${JAR}:$(find . -name 'jnetpcap*.jar' | head -n1):lib/*:build/libs/*"

for CLS in cic.cs.unb.ca.ifm.Cmd cic.cs.unb.ca.ifm.CICFlowMeter; do
  if java -Djava.library.path="${JNETPCAP_DIR}" -cp "${CP}" "${CLS}" "${PCAP}" "${OUT}" 2>/tmp/err; then
    exit 0
  fi
done
echo "CICFlowMeter CLI invocation failed:" >&2
cat /tmp/err >&2
exit 1
