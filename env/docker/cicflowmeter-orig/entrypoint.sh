#!/usr/bin/env bash
# Run CICFlowMeter's command-line flow generator on a pcap.
#   cfm-run <pcap> <outdir>   ->   <outdir>/<name>_Flow.csv
# Invokes the CLI class (cic.cs.unb.ca.ifm.Cmd) against the staged distribution
# classpath, with the bundled jnetpcap native lib on java.library.path.
set -euo pipefail
PCAP="$1"; OUT="$2"
DIST=/opt/CICFlowMeter/build/install/CICFlowMeter
CP="${DIST}/lib/*"

for CLS in cic.cs.unb.ca.ifm.Cmd cic.cs.unb.ca.ifm.CICFlowMeter; do
  if java -Djava.library.path=/usr/lib -cp "${CP}" "${CLS}" "${PCAP}" "${OUT}" 2>/tmp/err; then
    exit 0
  fi
done
echo "CICFlowMeter CLI invocation failed:" >&2
cat /tmp/err >&2
exit 1
