// flow_assemble.cpp
//
// Fast PcapPlusPlus-based flow assembler. A byte-for-byte reimplementation of the
// Python reference assembler `src/nids_xstudy/assembly/assembler.py`.
//
// Design note: PcapPlusPlus is used ONLY as a fast, format-agnostic (pcap +
// pcapng) raw-packet reader -- it hands us the raw link-layer frame bytes, the
// timestamp, and the original wire length. ALL L2/L3/L4 parsing, flow keying,
// segmentation and IP-address string formatting replicate read_packets() /
// _Flow / assemble() exactly, using libc inet_ntop() so address strings are
// identical to Python's socket.inet_ntoa / socket.inet_ntop (same glibc call).
//
// This keeps the semantics independent of PcapPlusPlus's own protocol dissector,
// so the output matches the scapy reference rather than PcapPlusPlus's opinions.
//
// CLI:  flow_assemble <in.pcap> <out_prefix>
//                     [--idle 120] [--active 1800]
//                     [--max-pkts 32] [--max-bytes 128]
// Writes:
//   <out_prefix>.meta.csv    one row per flow (see header below)
//   <out_prefix>.images.bin  raw uint8, n_flows * max_pkts * max_bytes, row-major
//   <out_prefix>.info.json   {n_flows,max_pkts,max_bytes,idle,active,ppp_version}

#include <arpa/inet.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "PcapFileDevice.h"
#include "PcapPlusPlusVersion.h"
#include "RawPacket.h"

// round(x, 6) with round-half-to-even, matching Python's round(). The default
// floating-point rounding mode (FE_TONEAREST) breaks exact .5 ties to even, as
// Python does.
static inline double round6(double x) { return std::nearbyint(x * 1e6) / 1e6; }

// Print a double with up to 6 decimals, trailing zeros trimmed. round6()'d
// values print as e.g. 0.0 -> "0", 0.01 -> "0.01", 150.0 -> "150". Re-parsed by
// Python float() this reproduces the reference's rounded floats exactly.
static void write_trimmed(FILE* f, double v) {
	char buf[64];
	int m = std::snprintf(buf, sizeof buf, "%.6f", v);
	int e = m;
	while (e > 0 && buf[e - 1] == '0') e--;
	if (e > 0 && buf[e - 1] == '.') e--;
	if (e == 0) { buf[0] = '0'; e = 1; }
	std::fwrite(buf, 1, e, f);
}

struct Flow {
	std::string init_ip;   // initiator (first packet) src ip
	int init_port = 0;     // initiator src port
	std::string sip, dip;  // stored 5-tuple, initiator/directed perspective
	int sport = 0, dport = 0, proto = 0;
	double t_start = 0.0, t_last = 0.0;
	long long n_pkts = 0, n_bytes = 0;
	long long pkts_fwd = 0, pkts_bwd = 0, bytes_fwd = 0, bytes_bwd = 0;
	std::vector<uint8_t> dirs;    // 0=fwd,1=bwd  (first max_pkts)
	std::vector<double> times;    // ts - t_start, round6
	std::vector<long long> sizes; // wire lengths
	std::vector<uint8_t> img;     // max_pkts * max_bytes, row-major, zero-padded
};

int main(int argc, char** argv) {
	if (argc < 3) {
		std::fprintf(stderr,
		    "usage: flow_assemble <in.pcap> <out_prefix> "
		    "[--idle 120] [--active 1800] [--max-pkts 32] [--max-bytes 128]\n");
		return 2;
	}
	const std::string in = argv[1];
	const std::string out_prefix = argv[2];
	double idle = 120.0, active = 1800.0;
	int max_pkts = 32, max_bytes = 128;

	for (int i = 3; i < argc; i++) {
		std::string a = argv[i];
		auto val = [&](const char* name) -> const char* {
			if (i + 1 >= argc) {
				std::fprintf(stderr, "missing value for %s\n", name);
				std::exit(2);
			}
			return argv[++i];
		};
		if (a == "--idle") idle = std::atof(val("--idle"));
		else if (a == "--active") active = std::atof(val("--active"));
		else if (a == "--max-pkts") max_pkts = std::atoi(val("--max-pkts"));
		else if (a == "--max-bytes") max_bytes = std::atoi(val("--max-bytes"));
		else {
			std::fprintf(stderr, "unknown argument: %s\n", a.c_str());
			return 2;
		}
	}
	if (max_pkts <= 0 || max_bytes <= 0) {
		std::fprintf(stderr, "--max-pkts and --max-bytes must be positive\n");
		return 2;
	}
	const size_t img_sz = static_cast<size_t>(max_pkts) * static_cast<size_t>(max_bytes);

	// getReader() auto-detects classic pcap vs pcapng from the file.
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(in);
	if (reader == nullptr) {
		std::fprintf(stderr, "cannot create a reader for %s\n", in.c_str());
		return 1;
	}
	if (!reader->open()) {
		std::fprintf(stderr, "cannot open %s\n", in.c_str());
		delete reader;
		return 1;
	}

	std::vector<std::unique_ptr<Flow>> all;   // every flow ever created (all get emitted)
	std::unordered_map<std::string, Flow*> active_flows;  // bidir key -> current open flow
	all.reserve(1u << 16);
	active_flows.reserve(1u << 16);

	pcpp::RawPacket rp;
	char ipbuf[INET6_ADDRSTRLEN];
	long long n_packets_read = 0;

	while (reader->getNextPacket(rp)) {
		n_packets_read++;
		const uint8_t* data = rp.getRawData();
		const int n = rp.getRawDataLen();  // captured length (caplen)
		if (n < 14) continue;

		timespec tsp = rp.getPacketTimeStamp();
		const double ts = static_cast<double>(tsp.tv_sec) +
		                  static_cast<double>(tsp.tv_nsec) * 1e-9;
		const long long wire_len = rp.getFrameLength();  // original on-wire length

		// Ethernet + optional 802.1Q / 802.1ad VLAN tags -> ethertype + IP offset.
		int etype = (data[12] << 8) | data[13];
		int off = 14;
		while ((etype == 0x8100 || etype == 0x88A8) && n >= off + 4) {
			etype = (data[off + 2] << 8) | data[off + 3];
			off += 4;
		}

		std::string sip, dip;
		int proto, sport = 0, dport = 0, l4;
		if (etype == 0x0800) {  // IPv4
			if (n < off + 20) continue;
			const int ihl = (data[off] & 0x0F) * 4;
			proto = data[off + 9];
			inet_ntop(AF_INET, data + off + 12, ipbuf, sizeof ipbuf); sip = ipbuf;
			inet_ntop(AF_INET, data + off + 16, ipbuf, sizeof ipbuf); dip = ipbuf;
			l4 = off + ihl;
		} else if (etype == 0x86DD) {  // IPv6 (no ext-header walk, matching reference)
			if (n < off + 40) continue;
			proto = data[off + 6];
			inet_ntop(AF_INET6, data + off + 8, ipbuf, sizeof ipbuf); sip = ipbuf;
			inet_ntop(AF_INET6, data + off + 24, ipbuf, sizeof ipbuf); dip = ipbuf;
			l4 = off + 40;
		} else {
			continue;  // non-IP
		}
		if ((proto == 6 || proto == 17) && n >= l4 + 4) {
			sport = (data[l4] << 8) | data[l4 + 1];
			dport = (data[l4 + 2] << 8) | data[l4 + 3];
		}

		// Order-independent bidirectional key. Endpoint ordering matches Python's
		// tuple comparison (sip,sport) <= (dip,dport): ip string first, then port.
		bool a_le_b;
		if (sip < dip) a_le_b = true;
		else if (sip > dip) a_le_b = false;
		else a_le_b = (sport <= dport);

		std::string key;
		key.reserve(sip.size() + dip.size() + 24);
		if (a_le_b) {
			key += sip; key.push_back('\x1f'); key += std::to_string(sport);
			key.push_back('\x1f'); key += dip; key.push_back('\x1f'); key += std::to_string(dport);
		} else {
			key += dip; key.push_back('\x1f'); key += std::to_string(dport);
			key.push_back('\x1f'); key += sip; key.push_back('\x1f'); key += std::to_string(sport);
		}
		key.push_back('\x1f'); key += std::to_string(proto);

		Flow* fl = nullptr;
		auto it = active_flows.find(key);
		if (it != active_flows.end()) {
			fl = it->second;
			// Strict '>' segmentation on idle and active timeouts.
			if ((ts - fl->t_last) > idle || (ts - fl->t_start) > active) {
				fl = nullptr;  // detach: the old flow stays in `all`, a new one starts
			}
		}
		if (fl == nullptr) {
			auto up = std::make_unique<Flow>();
			fl = up.get();
			fl->init_ip = sip; fl->init_port = sport;
			fl->sip = sip; fl->sport = sport; fl->dip = dip; fl->dport = dport;
			fl->proto = proto;
			fl->t_start = fl->t_last = ts;
			fl->dirs.reserve(max_pkts);
			fl->times.reserve(max_pkts);
			fl->sizes.reserve(max_pkts);
			fl->img.assign(img_sz, 0);
			all.push_back(std::move(up));
			active_flows[key] = fl;
		}

		const bool fwd = (sport == fl->init_port) && (sip == fl->init_ip);
		fl->t_last = ts;
		fl->n_pkts += 1;
		fl->n_bytes += wire_len;
		if (fwd) { fl->pkts_fwd++; fl->bytes_fwd += wire_len; }
		else { fl->pkts_bwd++; fl->bytes_bwd += wire_len; }

		if (static_cast<int>(fl->dirs.size()) < max_pkts) {
			const int i = static_cast<int>(fl->dirs.size());
			fl->dirs.push_back(fwd ? 0 : 1);
			fl->times.push_back(round6(ts - fl->t_start));
			fl->sizes.push_back(wire_len);
			const int avail = n - off;  // IP-layer bytes captured (data[off:])
			const int take = avail < max_bytes ? avail : max_bytes;
			if (take > 0)
				std::memcpy(&fl->img[static_cast<size_t>(i) * max_bytes], data + off, take);
		}
	}
	reader->close();
	delete reader;

	// Deterministic order: (t_start, src_ip, src_port, dst_ip, dst_port, proto).
	std::sort(all.begin(), all.end(),
	          [](const std::unique_ptr<Flow>& A, const std::unique_ptr<Flow>& B) {
		          const Flow* a = A.get();
		          const Flow* b = B.get();
		          if (a->t_start != b->t_start) return a->t_start < b->t_start;
		          if (a->sip != b->sip) return a->sip < b->sip;
		          if (a->sport != b->sport) return a->sport < b->sport;
		          if (a->dip != b->dip) return a->dip < b->dip;
		          if (a->dport != b->dport) return a->dport < b->dport;
		          return a->proto < b->proto;
	          });

	// ---- meta.csv --------------------------------------------------------------
	FILE* mf = std::fopen((out_prefix + ".meta.csv").c_str(), "wb");
	if (!mf) { std::fprintf(stderr, "cannot write %s.meta.csv\n", out_prefix.c_str()); return 1; }
	std::fputs("flow_id,src_ip,src_port,dst_ip,dst_port,proto,t_start,t_end,duration,"
	           "n_pkts,n_bytes,pkts_fwd,pkts_bwd,bytes_fwd,bytes_bwd,seq_len,"
	           "dirs,times,sizes\n",
	           mf);
	for (size_t i = 0; i < all.size(); i++) {
		const Flow* a = all[i].get();
		const double dur = round6(a->t_last - a->t_start);
		std::fprintf(mf, "%zu,%s,%d,%s,%d,%d,%.6f,%.6f,", i, a->sip.c_str(), a->sport,
		             a->dip.c_str(), a->dport, a->proto, a->t_start, a->t_last);
		write_trimmed(mf, dur);
		std::fprintf(mf, ",%lld,%lld,%lld,%lld,%lld,%lld,%zu,", a->n_pkts, a->n_bytes,
		             a->pkts_fwd, a->pkts_bwd, a->bytes_fwd, a->bytes_bwd, a->dirs.size());
		for (size_t k = 0; k < a->dirs.size(); k++) {
			if (k) std::fputc(' ', mf);
			std::fputc('0' + a->dirs[k], mf);
		}
		std::fputc(',', mf);
		for (size_t k = 0; k < a->times.size(); k++) {
			if (k) std::fputc(' ', mf);
			write_trimmed(mf, a->times[k]);
		}
		std::fputc(',', mf);
		for (size_t k = 0; k < a->sizes.size(); k++) {
			if (k) std::fputc(' ', mf);
			std::fprintf(mf, "%lld", a->sizes[k]);
		}
		std::fputc('\n', mf);
	}
	std::fclose(mf);

	// ---- images.bin ------------------------------------------------------------
	FILE* imgf = std::fopen((out_prefix + ".images.bin").c_str(), "wb");
	if (!imgf) { std::fprintf(stderr, "cannot write %s.images.bin\n", out_prefix.c_str()); return 1; }
	for (size_t i = 0; i < all.size(); i++)
		std::fwrite(all[i]->img.data(), 1, img_sz, imgf);
	std::fclose(imgf);

	// ---- info.json -------------------------------------------------------------
	FILE* jf = std::fopen((out_prefix + ".info.json").c_str(), "wb");
	if (!jf) { std::fprintf(stderr, "cannot write %s.info.json\n", out_prefix.c_str()); return 1; }
	std::fprintf(jf,
	             "{\"n_flows\": %zu, \"max_pkts\": %d, \"max_bytes\": %d, "
	             "\"idle\": %g, \"active\": %g, \"ppp_version\": \"%s\"}\n",
	             all.size(), max_pkts, max_bytes, idle, active,
	             pcpp::getPcapPlusPlusVersion().c_str());
	std::fclose(jf);

	std::fprintf(stderr, "flow_assemble: read %lld packets -> %zu flows\n",
	             n_packets_read, all.size());
	return 0;
}
