# CICFlowMeter (ORIGINAL, ahlashkari) — the v4 artifact used to generate the
# published CICIDS2017 features. Java + gradle + jnetpcap native lib.
#
# Reproducibility: pin CFM_REF to a commit SHA before the real extraction runs
# (default branch shown only to bootstrap). Build:
#   docker build -t nids-xstudy/cicflowmeter-orig:v4 \
#     --build-arg CFM_REF=<sha> env/docker/cicflowmeter-orig
FROM openjdk:8-jdk-slim

ARG CFM_REPO=https://github.com/ahlashkari/CICFlowMeter.git
ARG CFM_REF=master
ENV TZ=UTC DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        git libpcap-dev ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone "${CFM_REPO}" CICFlowMeter \
    && cd CICFlowMeter && git checkout "${CFM_REF}"

WORKDIR /opt/CICFlowMeter
# Build the fat/exec jar. Task name varies by version; try the common ones.
RUN chmod +x gradlew \
    && (./gradlew --no-daemon jar \
        || ./gradlew --no-daemon build -x test \
        || ./gradlew --no-daemon shadowJar)

COPY entrypoint.sh /usr/local/bin/cfm
RUN chmod +x /usr/local/bin/cfm
ENTRYPOINT ["/usr/local/bin/cfm"]
