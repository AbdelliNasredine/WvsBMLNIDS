# Argus (argus-server + argus-clients). Bidirectional biflow mode.
#   docker build -t nids-xstudy/argus:latest env/docker/argus
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive TZ=UTC
RUN apt-get update && apt-get install -y --no-install-recommends \
        argus-server argus-client ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/argus-extract
RUN chmod +x /usr/local/bin/argus-extract
ENTRYPOINT ["/usr/local/bin/argus-extract"]
