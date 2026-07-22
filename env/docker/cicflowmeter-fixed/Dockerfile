# CICFlowMeter (DistriNet FIXED fork, GintsEngelen) — RQ4 comparison target.
# Corrects TCP flag counting, FIN/RST flow termination (eliminates the "TCP
# appendix" flows), duplicate + timeout handling (Engelen et al., WTMC 2021).
# IDENTICAL build recipe to cicflowmeter-orig to isolate the code delta.
#   docker build -t nids-xstudy/cicflowmeter-fixed:distrinet \
#     --build-arg CFM_REF=<sha> env/docker/cicflowmeter-fixed
FROM eclipse-temurin:8-jdk-jammy

ARG CFM_REPO=https://github.com/GintsEngelen/CICFlowMeter.git
ARG CFM_REF=master
ENV TZ=UTC DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        git libpcap-dev tzdata ca-certificates maven \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone "${CFM_REPO}" CICFlowMeter && cd CICFlowMeter && git checkout "${CFM_REF}"

WORKDIR /opt/CICFlowMeter
ENV JNP=jnetpcap/linux/jnetpcap-1.4.r1425
RUN cp ${JNP}/*.so /usr/lib/ && ldconfig || true
ENV LD_LIBRARY_PATH=/usr/lib
RUN mvn -q install:install-file -Dfile=${JNP}/jnetpcap.jar \
        -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar
RUN chmod +x gradlew && ./gradlew --no-daemon installDist \
    && ls build/install/CICFlowMeter/lib | head

COPY entrypoint.sh /usr/local/bin/cfm-run
RUN chmod +x /usr/local/bin/cfm-run
ENTRYPOINT ["/usr/local/bin/cfm-run"]
