#!/usr/bin/env bash
# Run CICFlowMeter's command-line flow generator on a pcap.
#   cfm-run <pcap> <outdir>   ->   <outdir>/<name>_Flow.csv
set -euo pipefail
PCAP="$1"; OUT="$2"
DIST=/opt/CICFlowMeter/build/install/CICFlowMeter
CP="${DIST}/lib/*"
# Large captures (e.g. DAPT2020 thursday-pvt: 89M packets) exhaust the default
# JVM heap; give it a generous cap. Output is unchanged for smaller captures.
XMX="${CFM_XMX:-40g}"

for CLS in cic.cs.unb.ca.ifm.Cmd cic.cs.unb.ca.ifm.CICFlowMeter; do
  if java -Xmx"${XMX}" -Djava.library.path=/usr/lib -cp "${CP}" "${CLS}" "${PCAP}" "${OUT}" 2>/tmp/err; then
    exit 0
  fi
done
echo "CICFlowMeter CLI invocation failed:" >&2
cat /tmp/err >&2
exit 1
