# PcapPlusPlus flow-assembler: a fast C++ replacement for the scapy reference
# assembler (src/nids_xstudy/assembly/assembler.py) for the black-box NFM study.
# PcapPlusPlus is used purely as a fast, format-agnostic (pcap + pcapng) raw
# packet reader; ALL flow keying / segmentation / parsing replicate the Python
# reference byte-for-byte (see flow_assemble.cpp).
#   docker build -t nids-xstudy/ppp-assembler:1 env/docker/ppp-assembler
#
# ---- build stage: build PcapPlusPlus (pinned tag) + compile the tool ----------
FROM debian:bookworm-slim AS build
ENV DEBIAN_FRONTEND=noninteractive TZ=UTC
# Pin a released tag for reproducibility (override with --build-arg PPP_REF=...).
ARG PPP_REF=v25.05

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates build-essential cmake libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone --depth 1 --branch "${PPP_REF}" \
        https://github.com/seladb/PcapPlusPlus.git PcapPlusPlus

# Build static Pcap++/Packet++/Common++ and install to /usr/local (default).
RUN cmake -S PcapPlusPlus -B PcapPlusPlus/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DPCAPPP_BUILD_EXAMPLES=OFF \
        -DPCAPPP_BUILD_TESTS=OFF \
    && cmake --build PcapPlusPlus/build -j"$(nproc)" \
    && cmake --install PcapPlusPlus/build

# Compile the tool against the installed PcapPlusPlus CMake package.
COPY flow_assemble.cpp CMakeLists.txt /opt/tool/
RUN cmake -S /opt/tool -B /opt/tool/build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /opt/tool/build -j"$(nproc)" \
    && cp /opt/tool/build/flow_assemble /usr/local/bin/flow_assemble \
    && strip /usr/local/bin/flow_assemble

# ---- runtime stage: slim image with just libpcap + libstdc++ + the binary -----
FROM debian:bookworm-slim AS runtime
ENV DEBIAN_FRONTEND=noninteractive TZ=UTC
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/flow_assemble /usr/local/bin/flow_assemble
ENTRYPOINT ["flow_assemble"]
