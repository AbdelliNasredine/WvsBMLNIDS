"""Synthetic smoke-test PCAP fixture with known ground truth.

Builds a small, fully deterministic Ethernet PCAP exercising the flow-accounting
edge cases that separate extractors (Phase-0 gate, plan section 4):

* a complete HTTP request/response over TCP with a graceful FIN teardown,
* a DNS query/response over UDP (2-packet bidirectional flow),
* a long-lived TCP session with a >idle-timeout gap (splits into 2 flows under a
  120 s idle timeout — the flow-segmentation edge case),
* a SYN-scan burst of single-packet, unanswered flows,
* a TCP flow terminated by a RST from the responder.

The module exposes :data:`GROUND_TRUTH` (asserted by tests) and
:func:`build_pcap` (writes the fixture). Timestamps are hardcoded so the file is
byte-reproducible: no wall-clock, no randomness.
"""
from __future__ import annotations

from pathlib import Path

# 2021-07-07 12:00:00 UTC — arbitrary fixed base so the fixture is reproducible.
BASE_EPOCH = 1625659200.0
IDLE_TIMEOUT_S = 120

FIXTURE_DIR = Path(__file__).resolve().parent
PCAP_PATH = FIXTURE_DIR / "smoke.pcap"

# Endpoints
CLIENT = "10.0.0.10"
CLIENT2 = "10.0.0.11"
CLIENT3 = "10.0.0.12"
WEB = "93.184.216.34"
DNS_SRV = "8.8.8.8"
SCANNER = "10.0.0.99"
SCAN_VICTIM = "10.0.0.50"
SCAN_SRC_PORT = 40003
SCAN_N_PORTS = 20  # dst ports 1..20

MAC_A = "02:00:00:00:00:01"
MAC_B = "02:00:00:00:00:02"


def build_pcap(path: Path | str = PCAP_PATH) -> Path:
    """Write the smoke fixture PCAP to ``path`` and return the path."""
    from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap  # noqa: local import

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pkts = []
    eth = Ether(src=MAC_A, dst=MAC_B)

    class Conn:
        """A stateful TCP connection emitting realistic seq/ack numbers.

        Degenerate (all-zero) seq/ack numbers confuse stateful analyzers like
        Zeek (they split a connection or flip direction); tracking seq/ack keeps
        the fixture a valid ground truth for both stateful (Zeek) and 5-tuple
        (NFStream) tools. `c` = client->server (fwd), `s` = server->client (bwd).
        """
        def __init__(self, c_ip, c_port, s_ip, s_port, c_isn, s_isn):
            self.cip, self.cp, self.sip, self.sp = c_ip, c_port, s_ip, s_port
            self.cseq, self.sseq = c_isn, s_isn

        def _emit(self, src, sport, dst, dport, flags, seq, ack, t, payload):
            p = eth / IP(src=src, dst=dst) / TCP(
                sport=sport, dport=dport, flags=flags, seq=seq,
                ack=(ack if "A" in flags else 0))
            if payload:
                p = p / Raw(load=b"x" * payload)
            p.time = t
            pkts.append(p)

        def c(self, flags, t, payload=0):  # client -> server (fwd)
            self._emit(self.cip, self.cp, self.sip, self.sp, flags,
                       self.cseq, self.sseq, t, payload)
            self.cseq += payload + (1 if ("S" in flags or "F" in flags) else 0)

        def s(self, flags, t, payload=0):  # server -> client (bwd)
            self._emit(self.sip, self.sp, self.cip, self.cp, flags,
                       self.sseq, self.cseq, t, payload)
            self.sseq += payload + (1 if ("S" in flags or "F" in flags) else 0)

    def udp(src, sport, dst, dport, t, payload=0):
        p = eth / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
        if payload:
            p = p / Raw(load=b"x" * payload)
        p.time = t
        pkts.append(p)

    t0 = BASE_EPOCH

    # 1) HTTP over TCP: handshake, GET, response, graceful FIN teardown.
    #    fwd = client->web ; expect syn_fwd=1 fin_fwd=1 syn_bwd=1 fin_bwd=1
    #    pkts_fwd=6 pkts_bwd=4
    http = Conn(CLIENT, 40001, WEB, 80, c_isn=1000, s_isn=9000)
    http.c("S", t0 + 0.00)                 # 1 fwd SYN
    http.s("SA", t0 + 0.01)                # 2 bwd SYN-ACK
    http.c("A", t0 + 0.02)                 # 3 fwd ACK
    http.c("PA", t0 + 0.03, payload=100)   # 4 fwd GET
    http.s("PA", t0 + 0.05, payload=500)   # 5 bwd response
    http.c("A", t0 + 0.06)                 # 6 fwd ACK
    http.s("FA", t0 + 0.10)                # 7 bwd FIN
    http.c("A", t0 + 0.11)                 # 8 fwd ACK
    http.c("FA", t0 + 0.12)                # 9 fwd FIN
    http.s("A", t0 + 0.13)                 # 10 bwd ACK

    # 2) DNS over UDP: query + response (2-packet bidirectional flow).
    udp(CLIENT, 50000, DNS_SRV, 53, t0 + 0.20, payload=30)
    udp(DNS_SRV, 53, CLIENT, 50000, t0 + 0.25, payload=90)

    # 3) Long TCP session with a >idle-timeout gap -> 2 flows @120s idle.
    lng = Conn(CLIENT2, 40002, WEB, 443, c_isn=2000, s_isn=7000)
    lng.c("S", t0 + 1.00)
    lng.s("SA", t0 + 1.01)
    lng.c("A", t0 + 1.02)
    lng.c("PA", t0 + 1.50, payload=200)          # segment A ends
    gap = t0 + 1.50 + (IDLE_TIMEOUT_S + 30)      # 150s gap
    lng.c("PA", gap + 0.00, payload=200)         # segment B
    lng.s("A", gap + 0.02)
    lng.c("FA", gap + 0.03)
    lng.s("A", gap + 0.04)

    # 4) SYN-scan burst: SCAN_N_PORTS unanswered single-SYN flows.
    for i, dport in enumerate(range(1, SCAN_N_PORTS + 1)):
        p = eth / IP(src=SCANNER, dst=SCAN_VICTIM) / TCP(
            sport=SCAN_SRC_PORT, dport=dport, flags="S", seq=3000 + i * 4096, ack=0)
        p.time = t0 + 2.0 + i * 0.001
        pkts.append(p)

    # 5) RST-terminated TCP flow: responder sends RST+ACK. NFStream keeps this as
    #    one flow; Zeek's stateful tracker splits it (orphans the SYN as S0 and
    #    flips the remainder) on this fast synthetic connection — a quirk that
    #    does not occur on real captures. The RST flag accounting is unaffected.
    rst = Conn(CLIENT3, 40010, WEB, 8080, c_isn=4000, s_isn=6000)
    rst.c("S", t0 + 3.00)
    rst.s("SA", t0 + 3.01)
    rst.c("A", t0 + 3.02)
    rst.c("PA", t0 + 3.03, payload=50)
    rst.s("RA", t0 + 3.05)                       # bwd RST+ACK (realistic reset)

    wrpcap(str(path), pkts)
    return path


# Ground truth asserted by tests. Keyed by a human label; each entry pins the
# 5-tuple and the invariants a *correct* extractor must reproduce for that flow.
GROUND_TRUTH = {
    "base_epoch": BASE_EPOCH,
    "idle_timeout_s": IDLE_TIMEOUT_S,
    # distinct 5-tuples in the capture
    "n_five_tuples": 1 + 1 + 1 + SCAN_N_PORTS + 1,  # http+dns+long+scan+rst = 24
    # flows NFStream should emit at 120s idle (long session splits into 2)
    "n_flows_idle120": 1 + 1 + 2 + SCAN_N_PORTS + 1,  # = 25
    "http": {
        "key": (CLIENT, 40001, WEB, 80, 6),
        "pkts_fwd": 6, "pkts_bwd": 4,
        "syn_fwd": 1, "syn_bwd": 1, "fin_fwd": 1, "fin_bwd": 1,
        "psh_fwd": 1, "psh_bwd": 1, "rst_fwd": 0, "rst_bwd": 0,
    },
    "dns": {
        "key": (CLIENT, 50000, DNS_SRV, 53, 17),
        "pkts_fwd": 1, "pkts_bwd": 1, "proto": 17,
    },
    "rst": {
        "key": (CLIENT3, 40010, WEB, 8080, 6),
        "pkts_fwd": 3, "pkts_bwd": 2,
        "syn_fwd": 1, "syn_bwd": 1, "rst_fwd": 0, "rst_bwd": 1, "fin_fwd": 0,
    },
    "scan": {
        "src_ip": SCANNER, "dst_ip": SCAN_VICTIM, "src_port": SCAN_SRC_PORT,
        "n_ports": SCAN_N_PORTS, "dst_ports": list(range(1, SCAN_N_PORTS + 1)),
        # each scan flow: single forward SYN, no response
        "pkts_fwd": 1, "pkts_bwd": 0, "syn_fwd": 1,
    },
    "long_session": {
        "key": (CLIENT2, 40002, WEB, 443, 6),
        "n_flows_at_idle120": 2,
    },
}


if __name__ == "__main__":
    p = build_pcap()
    print(f"wrote {p} ({p.stat().st_size} bytes)")
