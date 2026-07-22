# Tranalyzer2 with core + default plugins (basicFlow, basicStats, tcpFlags,
# pktSIATHisto are all in the default set). autogen.sh builds core + defaults
# via the meson backend.
#
# The source tarball is fetched to vendor/ first (the tranalyzer.com server is
# very slow, ~20 min) and COPYed in, so image rebuilds don't re-download:
#   ./env/docker/tranalyzer/fetch_tarball.sh    # one-time, writes vendor/t2.tar.gz
#   docker build -t nids-xstudy/tranalyzer:0.9.4 env/docker/tranalyzer
# NOTE: the tarball is tranalyzer2-0.9.4lmw1.tar.gz but extracts to
# tranalyzer2-0.9.4/ (the codename is only in the filename).
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive TZ=UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential meson ninja-build pkg-config \
        zlib1g-dev libpcap-dev libssl-dev bison flex \
        autoconf automake libtool gawk ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
COPY vendor/t2.tar.gz /opt/t2.tar.gz
RUN tar xzf t2.tar.gz && rm t2.tar.gz && mv tranalyzer2-* tranalyzer2

WORKDIR /opt/tranalyzer2
# autogen.sh (== t2build) builds Tranalyzer2 + the default plugin set. It prompts
# "Running as root... Proceed anyway (y/N)?" so we feed it `yes`. We do NOT use
# pipefail: `yes` exits 141 (SIGPIPE) when the pipe closes after a SUCCESSFUL
# build, which would falsely fail the step. The binary-existence check below is
# the real gate on build success.
RUN yes | ./autogen.sh 2>&1 | tail -60 || true
# fail the build if autogen did not actually produce the binary
RUN bin=$(find / -name 'tranalyzer' -type f 2>/dev/null | head -1); \
    echo "tranalyzer binary: ${bin:-NOT FOUND}"; test -n "$bin" \
    && ln -sf "$bin" /usr/local/bin/tranalyzer

COPY entrypoint.sh /usr/local/bin/t2-extract
RUN chmod +x /usr/local/bin/t2-extract
ENTRYPOINT ["/usr/local/bin/t2-extract"]
