#!/usr/bin/env bash
# Run CICFlowMeter's command-line flow generator on a pcap.
#   cfm <pcap> <outdir>
# Locates the built jar and the bundled jnetpcap native library, then invokes
# the CLI class. Both the classic (cic.cs.unb.ca.ifm.Cmd) and newer CLI class
# names are attempted.
set -euo pipefail
PCAP="$1"; OUT="$2"
cd /opt/CICFlowMeter

# jnetpcap native library ships in the repo; find its dir.
JNETPCAP_DIR="$(dirname "$(find . -name 'libjnetpcap.so' | head -n1)")"
JAR="$(find build -name '*.jar' | grep -viE 'sources|javadoc' | head -n1)"

# Classpath: built jar + any dependency jars + jnetpcap jar.
CP="${JAR}:$(find . -name 'jnetpcap*.jar' | head -n1):lib/*:build/libs/*"

for CLS in cic.cs.unb.ca.ifm.Cmd cic.cs.unb.ca.ifm.CICFlowMeter; do
  if java -Djava.library.path="${JNETPCAP_DIR}" -cp "${CP}" "${CLS}" "${PCAP}" "${OUT}" 2>/tmp/err; then
    exit 0
  fi
done
echo "CICFlowMeter CLI invocation failed:" >&2
cat /tmp/err >&2
exit 1
