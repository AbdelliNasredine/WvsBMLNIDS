FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive TZ=UTC

ARG ARGUS_REPO=https://github.com/openargus/argus.git
ARG CLIENTS_REPO=https://github.com/openargus/clients.git
ARG ARGUS_REF=
ARG CLIENTS_REF=

RUN apt-get update && apt-get install -y --no-install-recommends \
        git build-essential bison flex libpcap-dev zlib1g-dev \
        libtirpc-dev libwrap0-dev ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone "${ARGUS_REPO}" argus \
    && if [ -n "${ARGUS_REF}" ]; then cd argus && git checkout "${ARGUS_REF}"; fi
RUN git clone "${CLIENTS_REPO}" clients \
    && if [ -n "${CLIENTS_REF}" ]; then cd clients && git checkout "${CLIENTS_REF}"; fi

# argus-server
RUN cd /opt/argus && ./configure && make && make install

# argus-clients
RUN cd /opt/clients && ./configure && make && make install
RUN ldconfig || true

COPY entrypoint.sh /usr/local/bin/argus-extract
RUN chmod +x /usr/local/bin/argus-extract
ENTRYPOINT ["/usr/local/bin/argus-extract"]
