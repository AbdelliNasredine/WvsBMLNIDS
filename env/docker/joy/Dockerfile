# Joy (cisco/joy, ARCHIVED) — per-flow JSON with packet length/IAT sequences.
# We derive statistical features from the sequences (methodology, unit-tested).
# --enable-gzip is required for gzipped output.
#   docker build -t nids-xstudy/joy:4.4.1 env/docker/joy
# v4.4.1 predates OpenSSL 3, so build on 20.04 (OpenSSL 1.1); 18.04 apt is EOL.
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates build-essential libssl-dev libpcap-dev \
        libcurl4-openssl-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/cisco/joy.git /opt/joy \
    && cd /opt/joy && git checkout v4.4.1 \
    && ./configure --enable-gzip && make clean && make
COPY entrypoint.sh /usr/local/bin/joy-run
RUN chmod +x /usr/local/bin/joy-run
ENTRYPOINT ["/usr/local/bin/joy-run"]
