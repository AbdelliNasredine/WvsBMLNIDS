# YAF + super_mediator + libfixbuf (CERT NetSA) — standards IPFIX probe.
# Matched 2.x stack (fixbuf major must match yaf & super_mediator).
#   docker build -t nids-xstudy/yaf:2.19.3 env/docker/yaf
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig LD_LIBRARY_PATH=/usr/local/lib

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config ca-certificates curl \
        libglib2.0-dev libpcap-dev libpcre2-dev zlib1g-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
# libfixbuf -> yaf -> super_mediator (build + install order matters; ldconfig
# after libfixbuf is essential).
RUN curl -fsSLO https://tools.netsa.cert.org/releases/libfixbuf-2.5.4.tar.gz \
    && tar xzf libfixbuf-2.5.4.tar.gz && cd libfixbuf-2.5.4 \
    && ./configure && make -j"$(nproc)" && make install && ldconfig
RUN curl -fsSLO https://tools.netsa.cert.org/releases/yaf-2.19.3.tar.gz \
    && tar xzf yaf-2.19.3.tar.gz && cd yaf-2.19.3 \
    && ./configure --enable-applabel --enable-plugins \
    && make -j"$(nproc)" && make install && ldconfig
RUN curl -fsSLO https://tools.netsa.cert.org/releases/super_mediator-1.13.2.tar.gz \
    && tar xzf super_mediator-1.13.2.tar.gz && cd super_mediator-1.13.2 \
    && ./configure --without-mysql && make -j"$(nproc)" && make install && ldconfig

COPY entrypoint.sh /usr/local/bin/yaf-run
RUN chmod +x /usr/local/bin/yaf-run
ENTRYPOINT ["/usr/local/bin/yaf-run"]
