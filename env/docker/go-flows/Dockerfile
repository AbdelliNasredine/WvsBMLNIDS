# go-flows (CN-TU/go-flows, TU Wien) — spec-driven IPFIX feature exporter.
# Only backend is libpcap (cgo). Feature specs are mounted at /specs at runtime.
#   docker build -t nids-xstudy/go-flows:9f5628c env/docker/go-flows
FROM golang:1.22-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libpcap-dev ca-certificates git && rm -rf /var/lib/apt/lists/*
ENV CGO_ENABLED=1
RUN go install github.com/CN-TU/go-flows@9f5628c1245634830be7972d2c2601335a7a0a15

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /go/bin/go-flows /usr/local/bin/go-flows
COPY entrypoint.sh /usr/local/bin/goflows-run
RUN chmod +x /usr/local/bin/goflows-run
ENTRYPOINT ["/usr/local/bin/goflows-run"]
