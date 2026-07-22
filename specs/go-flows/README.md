# go-flows feature specifications

Two versioned IPFIX feature-spec JSONs drive go-flows (CN-TU/go-flows):

- `common.json`  — the R-common information elements (mappable across all tools):
  flowStart/EndMilliseconds, source/destination IPv4 + transport ports,
  protocolIdentifier, packet/octetDeltaCount (+ reverse), TCP flag counts.
- `maximal.json` — the widest feature set go-flows can export (R-native for
  go-flows).

Authored from the go-flows feature-spec format; validated on the smoke PCAP.
Filled in during the go-flows build task.
