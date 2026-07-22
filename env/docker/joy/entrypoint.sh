#!/usr/bin/env bash
# joy-run <pcap> <outdir>  ->  <outdir>/<name>.json.gz  (gzipped NDJSON)
# First JSON line is a version/config header (skip in parser). num_pkts=200 keeps
# more of the per-packet sequence for statistical-feature derivation.
set -euo pipefail
PCAP="$1"; OUT="$2"
NAME="$(basename "${PCAP}")"
/opt/joy/bin/joy bidir=1 dist=1 num_pkts=200 "${PCAP}" > "${OUT}/${NAME}.json.gz"
