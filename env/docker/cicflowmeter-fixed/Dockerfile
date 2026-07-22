# CICFlowMeter (DistriNet FIXED fork, GintsEngelen) — RQ4 comparison target.
# Corrects TCP flag counting, FIN/RST flow termination, duplicate + timeout
# handling (Engelen, Rimmer, Joosen, WTMC 2021).
#
#   docker build -t nids-xstudy/cicflowmeter-fixed:distrinet \
#     --build-arg CFM_REF=<sha> env/docker/cicflowmeter-fixed
FROM openjdk:8-jdk-slim

ARG CFM_REPO=https://github.com/GintsEngelen/CICFlowMeter.git
ARG CFM_REF=master
ENV TZ=UTC DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        git libpcap-dev ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone "${CFM_REPO}" CICFlowMeter \
    && cd CICFlowMeter && git checkout "${CFM_REF}"

WORKDIR /opt/CICFlowMeter
RUN chmod +x gradlew \
    && (./gradlew --no-daemon jar \
        || ./gradlew --no-daemon build -x test \
        || ./gradlew --no-daemon shadowJar)

COPY entrypoint.sh /usr/local/bin/cfm
RUN chmod +x /usr/local/bin/cfm
ENTRYPOINT ["/usr/local/bin/cfm"]
