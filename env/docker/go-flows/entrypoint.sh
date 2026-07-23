#!/usr/bin/env bash

set -euo pipefail
PCAP="$1"; OUT="$2"; SPEC="${3:-common}"
NAME="$(basename "${PCAP}")"
go-flows run features "/specs/${SPEC}.json" \
    export csv "${OUT}/${NAME}.csv" \
    source libpcap "${PCAP}"
