# Extractor build recipes — pinned versions, commands, field mappings

Verified upstream build/run recipes for the v2 tool matrix. Pins go in each
Dockerfile; this is the human-readable index + the parser field maps.

> **Dropped from the final tool set** (recipes kept for reference only):
> **flowtbag** (2015 cgo incompatible with modern Go + no start-time),
> **nProbe** (requires an ntop license file to run in-container), and
> **NTLFlowLyzer** (pure-Python; ~15 h to extract CICIDS2017 — impractically slow).
> The active 9 tools are NFStream, Zeek, Tranalyzer, Argus, CICFlowMeter-orig,
> CICFlowMeter-fixed, go-flows, YAF, Joy.

## Pinned versions
| Tool | Pin | Source |
|---|---|---|
| NTLFlowLyzer | tag `v0.2.0` (setup.py version string is wrong — trust the tag) | github.com/ahlashkari/NTLFlowLyzer |
| flowtbag | commit `e322e4a401418f044ddae1d79c50bdf52aa65fa0` (archived, GOPATH-era) | github.com/DanielArndt/flowtbag |
| go-flows | commit `9f5628c1245634830be7972d2c2601335a7a0a15` | github.com/CN-TU/go-flows |
| YAF stack | libfixbuf 2.5.4 + yaf 2.19.3 + super_mediator 1.13.2 (matched 2.x) | tools.netsa.cert.org/releases/ |
| Joy | tag `v4.4.1` | github.com/cisco/joy (archived) |
| nProbe | rolling (vendor the resolved .deb; record `dpkg-query -W nprobe`) | packages.ntop.org |

## Run commands (offline pcap)
- **NTLFlowLyzer:** `ntlflowlyzer -c config.json` (keys `pcap_file_address`,
  `output_file_address`, `number_of_threads`>=3, `label`). TCP-only. NO pcapng.
  Timestamp = naive LOCAL string → run container `TZ=UTC`. No end col.
- **flowtbag:** `flowtbag file.pcap > out.csv` (no header, 45 positional cols,
  stderr=progress). Times INTEGER SECONDS (do NOT /1e6). NO absolute start-time
  column. Drops flows lacking bidirectional payload. IPv4+Ethernet only.
- **go-flows:** `go-flows run features spec.json export csv out.csv source libpcap in.pcap`.
  Counts are MERGED totals (no per-direction). flowStart/EndMilliseconds present.
- **YAF:** `yaf --in x.pcap --out x.ipfix` (biflow default; no --uniflow, no --silk)
  then `super_mediator --in x.ipfix --out x.json -m JSON` (NDJSON, one obj/line;
  `{"stats":...}` lines interleaved). Per-direction counts + TCP flags. Times UTC.
- **Joy:** `joy bidir=1 dist=1 num_pkts=200 <pcap> > out.json.gz` (gzip even w/o .gz;
  first line is a version header — skip). Derive per-direction stats from `packets[]`.
- **nProbe:** `nprobe -i x.pcap -n none -T "<template>" --dump-format t -P /out
  --csv-separator , --dont-nest-dump-dirs`. DEMO CAPS AT 25,000 FLOWS → needs
  academic license for full CICIDS2017.

## Parser field maps (tool column -> canonical)
- **NTLFlowLyzer:** src_ip,dst_ip,src_port,dst_port; protocol (literal "TCP");
  timestamp (local→UTC str); duration (s); fwd_packets_count/bwd_packets_count;
  fwd_total_payload_bytes/bwd_total_payload_bytes; {fwd,bwd}_{syn,fin,rst,psh,ack,urg,cwr,ece}_flag_counts.
- **flowtbag (positional):** 1 srcip,2 srcport,3 dstip,4 dstport,5 proto,
  6 total_fpackets,7 total_fvolume,8 total_bpackets,9 total_bvolume,26 duration(s),
  39 fpsh_cnt,40 bpsh_cnt,41 furg_cnt,42 burg_cnt,43 total_fhlen,44 total_bhlen,45 dscp.
  (No start time → cannot time-window label directly; align via 5-tuple in Phase 2.)
- **go-flows:** flowStartMilliseconds,flowEndMilliseconds,sourceIPAddress,
  destinationIPAddress,sourceTransportPort,destinationTransportPort,protocolIdentifier,
  packetTotalCount(merged),octetTotalCount(merged),tcp{Syn,Fin,Rst,Psh,Ack,Urg}TotalCount.
- **YAF/super_mediator JSON:** sourceIPv4Address,destinationIPv4Address,
  sourceTransportPort,destinationTransportPort,protocolIdentifier;
  stimems/etimems (epoch-ms UTC, ids 20/21) or flowStart/EndMilliseconds (ISO);
  packetTotalCount/reversePacketTotalCount; octetTotalCount/reverseOctetTotalCount;
  initialTCPFlags/reverseInitialTCPFlags, unionTCPFlags/reverseUnionTCPFlags.
- **Joy JSON:** sa,da,sp,dp,pr; time_start,time_end (epoch sec.µs);
  num_pkts_out/num_pkts_in, bytes_out/bytes_in; packets[]={b,dir(">"=out/sa→da,"<"=in),ipt(ms)}.

See the git history of this file / each Dockerfile for provenance.
