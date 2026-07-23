# Tranalyzer2 with core + default plugins (basicFlow, basicStats, tcpFlags,
# pktSIATHisto are all in the default set). 
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

RUN yes | ./autogen.sh 2>&1 | tail -60 || true
RUN bin=$(find / -name 'tranalyzer' -type f 2>/dev/null | head -1); \
    echo "tranalyzer binary: ${bin:-NOT FOUND}"; test -n "$bin" \
    && ln -sf "$bin" /usr/local/bin/tranalyzer

COPY entrypoint.sh /usr/local/bin/t2-extract
RUN chmod +x /usr/local/bin/t2-extract
ENTRYPOINT ["/usr/local/bin/t2-extract"]
