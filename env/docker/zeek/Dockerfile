FROM zeek/zeek:6.0.0

COPY flowfeatures.zeek /opt/zeek/share/zeek/site/flowfeatures.zeek

RUN zeek -C -e 'exit(0)' /opt/zeek/share/zeek/site/flowfeatures.zeek

ENTRYPOINT ["zeek"]
