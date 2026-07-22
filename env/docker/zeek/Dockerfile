# Zeek extractor image (LTS, version-pinned).
# conn.log gives per-direction packet/byte counts + duration + history; the
# bundled flowfeatures.zeek adds per-direction TCP flag counts (SYN/FIN/RST/
# PSH/ACK/URG) which conn.log does not provide natively.
FROM zeek/zeek:6.0.0

COPY flowfeatures.zeek /opt/zeek/share/zeek/site/flowfeatures.zeek

# Sanity: fail the build if the script does not parse.
RUN zeek -C -e 'exit(0)' /opt/zeek/share/zeek/site/flowfeatures.zeek

ENTRYPOINT ["zeek"]
