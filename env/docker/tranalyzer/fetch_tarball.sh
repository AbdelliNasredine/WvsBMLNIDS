#!/usr/bin/env bash
# One-time fetch of the Tranalyzer2 source tarball into vendor/ (the upstream
# server is very slow, ~20 min). Run before `docker build` of the tranalyzer
# image. vendor/ is gitignored.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
URL="https://tranalyzer.com/download/tranalyzer/tranalyzer2-0.9.4lmw1.tar.gz"
mkdir -p "$DIR/vendor"
echo "downloading (slow, ~20 min) ..."
wget -q --show-progress "$URL" -O "$DIR/vendor/t2.tar.gz"
echo "wrote $DIR/vendor/t2.tar.gz ($(stat -c%s "$DIR/vendor/t2.tar.gz" 2>/dev/null || echo '?') bytes)"
