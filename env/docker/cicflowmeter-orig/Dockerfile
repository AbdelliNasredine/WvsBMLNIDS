# CICFlowMeter (ORIGINAL, ahlashkari) — the v4 artifact used to generate the
# published CICIDS2017 features. Java + gradle + bundled jnetpcap native libs.
# RQ4 lineage anchor. Pin CFM_REF to a commit SHA before the real runs.
#   docker build -t nids-xstudy/cicflowmeter-orig:v4 \
#     --build-arg CFM_REF=<sha> env/docker/cicflowmeter-orig
FROM eclipse-temurin:8-jdk-jammy

ARG CFM_REPO=https://github.com/ahlashkari/CICFlowMeter.git
ARG CFM_REF=master
ENV TZ=UTC DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        git libpcap-dev tzdata ca-certificates maven \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone "${CFM_REPO}" CICFlowMeter && cd CICFlowMeter && git checkout "${CFM_REF}"

WORKDIR /opt/CICFlowMeter
# Install ONLY the jnetpcap 1.4.r1425 native libs (the repo also bundles 1.3.0;
# mixing versions breaks the native protocol scanner -> "MAX_ID_COUNT" /
# all-packets-discarded). Pin to r1425 to match the 1.4.1 jar dependency.
ENV JNP=jnetpcap/linux/jnetpcap-1.4.r1425
RUN cp ${JNP}/*.so /usr/lib/ && ldconfig || true
ENV LD_LIBRARY_PATH=/usr/lib

# jnetpcap 1.4.1 is NOT on Maven Central; the build declares it as a normal
# dependency resolved via mavenLocal(). Install the matching r1425 jar.
RUN mvn -q install:install-file -Dfile=${JNP}/jnetpcap.jar \
        -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar

# Build + stage the distribution (dependency jars land in build/install/.../lib).
RUN chmod +x gradlew && ./gradlew --no-daemon installDist \
    && ls build/install/CICFlowMeter/lib | head

COPY entrypoint.sh /usr/local/bin/cfm-run
RUN chmod +x /usr/local/bin/cfm-run
ENTRYPOINT ["/usr/local/bin/cfm-run"]
