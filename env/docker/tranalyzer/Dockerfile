# Tranalyzer2 with core + basicFlow, basicStats, tcpFlags, pktSIATHisto plugins.
# Tranalyzer is distributed as a source tarball from tranalyzer.com; pin
# T2_VERSION for reproducibility.
#   docker build -t nids-xstudy/tranalyzer:0.9.2 \
#     --build-arg T2_VERSION=0.9.2 env/docker/tranalyzer
#
# UNVERIFIED: build recipe follows the upstream install docs; validate on the
# smoke pcap once Docker is available.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive TZ=UTC
ARG T2_VERSION=0.9.2
ARG T2_URL=https://tranalyzer.com/download/tranalyzer/tranalyzer2-${T2_VERSION}.tar.gz

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf automake libtool pkg-config \
        zlib1g-dev libpcap-dev libssl-dev bison flex wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN wget -q "${T2_URL}" -O t2.tar.gz && tar xzf t2.tar.gz && rm t2.tar.gz \
    && mv tranalyzer2-* tranalyzer2
WORKDIR /opt/tranalyzer2
# autogen builds core + the default plugin set (incl. the four we need).
RUN ./autogen.sh -f || ./autogen.sh
ENV PATH="/root/.local/tranalyzer2/:/root/bin:${PATH}"
COPY entrypoint.sh /usr/local/bin/t2-extract
RUN chmod +x /usr/local/bin/t2-extract
ENTRYPOINT ["/usr/local/bin/t2-extract"]
