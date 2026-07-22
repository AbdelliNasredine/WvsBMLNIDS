"""Reference flow assembler: PCAP -> per-flow packet sequences.

Segmentation policy (the reference, ablatable in Phase B3):
  * order-independent bidirectional 5-tuple key (matches canonical.bidirectional_key)
  * 120 s idle timeout, 1800 s active timeout
  * flow direction = the endpoint that sent the first packet (initiator = fwd)

Packet reading strips L2 and keeps IP-layer bytes onward. TCP/UDP ports are
parsed; other L4 protocols get port 0. The default 32x128 byte image is a
superset of every model's default truncation; per-model builders and the
truncation ablation cut it down.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class AssemblyConfig:
    idle_timeout: float = 120.0
    active_timeout: float = 1800.0
    max_pkts: int = 32          # packets per flow retained in the image
    max_bytes: int = 128        # IP-layer bytes per packet retained
    name: str = "reference"

    def as_dict(self) -> dict:
        return asdict(self)


ASSEMBLY_DEFAULTS = AssemblyConfig()

# columns emitted per flow (the packet image is stored separately, see assemble())
_META_COLS = ["flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "proto",
              "t_start", "t_end", "duration", "n_pkts", "n_bytes",
              "pkts_fwd", "pkts_bwd", "bytes_fwd", "bytes_bwd", "seq_len"]


def _bidir_key(sip, sport, dip, dport, proto):
    a, b = (sip, sport), (dip, dport)
    lo, hi = (a, b) if a <= b else (b, a)
    return (lo[0], lo[1], hi[0], hi[1], proto)


def read_packets(pcap_path):
    """Yield (ts, sip, sport, dip, dport, proto, wire_len, ip_bytes) per packet.

    Fast path: scapy's RawPcapReader (raw bytes, ~70x faster than full
    dissection, handles pcap and pcapng) + manual Ethernet/IP/TCP/UDP header
    parsing. L2 (incl. VLAN tags) is stripped; ip_bytes is the IP header onward.
    Non-IP packets are skipped. Validated against the dissecting reader.
    """
    import socket
    from scapy.all import RawPcapReader  # local import

    rd = RawPcapReader(str(pcap_path))
    try:
        for data, meta in rd:
            n = len(data)
            if n < 14:
                continue
            # timestamp: pcapng (tshigh/tslow * tsresol) or classic pcap (sec/usec)
            tsh = getattr(meta, "tshigh", None)
            if tsh is not None:
                raw = (tsh << 32) | meta.tslow
                tsr = getattr(meta, "tsresol", 1e-6) or 1e-6
                # tsresol may be a fraction (1e-6) or ticks-per-second (1e6);
                # normalize both to seconds.
                ts = raw / tsr if tsr > 1 else raw * tsr
                wire_len = getattr(meta, "wirelen", n)
            else:
                ts = meta.sec + meta.usec * 1e-6
                wire_len = getattr(meta, "wirelen", n)
            # Ethernet + optional VLAN tags -> ethertype + IP offset
            etype = (data[12] << 8) | data[13]
            off = 14
            while etype in (0x8100, 0x88A8) and n >= off + 4:  # 802.1Q / 802.1ad
                etype = (data[off + 2] << 8) | data[off + 3]
                off += 4
            if etype == 0x0800:  # IPv4
                if n < off + 20:
                    continue
                ihl = (data[off] & 0x0F) * 4
                proto = data[off + 9]
                sip = socket.inet_ntoa(data[off + 12:off + 16])
                dip = socket.inet_ntoa(data[off + 16:off + 20])
                l4 = off + ihl
            elif etype == 0x86DD:  # IPv6 (no ext-header walk; ports read if direct TCP/UDP)
                if n < off + 40:
                    continue
                proto = data[off + 6]
                sip = socket.inet_ntop(socket.AF_INET6, data[off + 8:off + 24])
                dip = socket.inet_ntop(socket.AF_INET6, data[off + 24:off + 40])
                l4 = off + 40
            else:
                continue
            sport = dport = 0
            if proto in (6, 17) and n >= l4 + 4:
                sport = (data[l4] << 8) | data[l4 + 1]
                dport = (data[l4 + 2] << 8) | data[l4 + 3]
            yield ts, sip, sport, dip, dport, proto, wire_len, bytes(data[off:])
    finally:
        rd.close()


class _Flow:
    __slots__ = ("init_src", "sip", "sport", "dip", "dport", "proto",
                 "t_start", "t_last", "n_pkts", "n_bytes",
                 "pkts_fwd", "pkts_bwd", "bytes_fwd", "bytes_bwd",
                 "dirs", "times", "sizes", "img", "cap")

    def __init__(self, sip, sport, dip, dport, proto, ts, cfg):
        self.init_src = (sip, sport)
        self.sip, self.sport, self.dip, self.dport, self.proto = sip, sport, dip, dport, proto
        self.t_start = self.t_last = ts
        self.n_pkts = self.n_bytes = 0
        self.pkts_fwd = self.pkts_bwd = self.bytes_fwd = self.bytes_bwd = 0
        self.dirs, self.times, self.sizes = [], [], []
        self.cap = cfg.max_pkts
        self.img = np.zeros((cfg.max_pkts, cfg.max_bytes), dtype=np.uint8)

    def add(self, ts, psip, psport, wire_len, raw, cfg):
        fwd = (psip, psport) == self.init_src
        self.t_last = ts
        self.n_pkts += 1
        self.n_bytes += wire_len
        if fwd:
            self.pkts_fwd += 1; self.bytes_fwd += wire_len
        else:
            self.pkts_bwd += 1; self.bytes_bwd += wire_len
        if len(self.dirs) < self.cap:
            i = len(self.dirs)
            self.dirs.append(0 if fwd else 1)
            self.times.append(round(ts - self.t_start, 6))
            self.sizes.append(int(wire_len))
            b = raw[:cfg.max_bytes]
            self.img[i, :len(b)] = np.frombuffer(b, dtype=np.uint8)


def assemble(pcap_path, cfg: AssemblyConfig = ASSEMBLY_DEFAULTS):
    """Assemble a PCAP into a per-flow table + a stacked uint8 packet-image array.

    Returns (meta: DataFrame[_META_COLS + seq columns], images: np.uint8
    [n_flows, max_pkts, max_bytes]). Row i of meta corresponds to images[i].
    """
    active: dict = {}
    done: list = []

    def close(fl):
        done.append(fl)

    for ts, sip, sport, dip, dport, proto, wlen, raw in read_packets(pcap_path):
        key = _bidir_key(sip, sport, dip, dport, proto)
        fl = active.get(key)
        if fl is not None:
            if (ts - fl.t_last) > cfg.idle_timeout or (ts - fl.t_start) > cfg.active_timeout:
                close(fl)
                fl = None
        if fl is None:
            fl = _Flow(sip, sport, dip, dport, proto, ts, cfg)
            active[key] = fl
        fl.add(ts, sip, sport, wlen, raw, cfg)
    for fl in active.values():
        close(fl)

    # deterministic order: by start time then key
    done.sort(key=lambda f: (f.t_start, f.sip, f.sport, f.dip, f.dport, f.proto))
    rows, imgs = [], []
    for i, f in enumerate(done):
        rows.append({
            "flow_id": i, "src_ip": f.sip, "src_port": f.sport, "dst_ip": f.dip,
            "dst_port": f.dport, "proto": f.proto, "t_start": f.t_start,
            "t_end": f.t_last, "duration": round(f.t_last - f.t_start, 6),
            "n_pkts": f.n_pkts, "n_bytes": f.n_bytes, "pkts_fwd": f.pkts_fwd,
            "pkts_bwd": f.pkts_bwd, "bytes_fwd": f.bytes_fwd, "bytes_bwd": f.bytes_bwd,
            "seq_len": len(f.dirs), "dirs": f.dirs, "times": f.times, "sizes": f.sizes,
        })
        imgs.append(f.img)
    meta = pd.DataFrame(rows, columns=_META_COLS + ["dirs", "times", "sizes"])
    images = np.stack(imgs) if imgs else np.zeros((0, cfg.max_pkts, cfg.max_bytes), np.uint8)
    return meta, images
