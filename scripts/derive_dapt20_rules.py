#!/usr/bin/env python
"""Derive DAPT2020 labeling artifacts from the dataset's CICFlowMeter CSVs.

The study labels each extractor's flows independently with a time+IP+port rules
engine (never reusing dataset-shipped per-flow labels). For DAPT2020 that works
only for the stages whose attacker endpoints are attack-exclusive:

  * Establish Foothold (Wed), Lateral Movement (Thu), Data Exfiltration (Fri)
    -> emitted as rules in data/labels/dapt20/rules.yaml.
  * Reconnaissance (Tue) CANNOT be separated by 5-tuple+time (the scanner/C&C
    IPs also generate thousands of benign flows to the same victim/ports in the
    same windows). Per the approved HYBRID decision we fall back to DAPT's own
    per-flow label for this ONE stage, projected onto our flows by 5-tuple +
    nearest-time. Those recon flows are dumped to recon_flows.parquet and applied
    at label time by nids_xstudy.labeling.dapt_recon.

The CSV Timestamp is local wall-clock (Arizona MST); pcaps store UTC epochs. The
offset is measured, not assumed (expect +7 h), and used to convert every window.

    python scripts/derive_dapt20_rules.py            # writes rules.yaml, recon_flows.parquet, report
    python scripts/derive_dapt20_rules.py --dry-run  # report only, no files written
"""
from __future__ import annotations

import argparse
import csv
import struct
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pandas as pd  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402

DATASET = "dapt20"
CLEAN_STAGES = ["Establish Foothold", "Lateral Movement", "Data Exfiltration"]
RECON_STAGE = "Reconnaissance"
GAP = timedelta(minutes=10)          # split attack flows into windows on >10 min gaps
PAD_S = 30                           # widen each derived window by +/- this many seconds
MCAST_PREFIXES = ("224.", "239.", "255.", "0.0.0.0")  # never treat as victim/attacker

# capture -> (pcap filename, csv filename, headerless?)
CAPS = {
    "monday-pub": ("enp0s3-monday.pcap", "enp0s3-monday.pcap_Flow.csv", False),
    "monday-pvt": ("enp0s3-monday-pvt.pcap", "enp0s3-monday-pvt.pcap_Flow.csv", False),
    "tuesday-pub": ("enp0s3-public-tuesday.pcap", "enp0s3-public-tuesday.pcap_Flow.csv", False),
    "tuesday-pvt": ("enp0s3-pvt-tuesday.pcap", "enp0s3-pvt-tuesday.pcap_Flow.csv", False),
    "wednesday-pub": ("enp0s3-public-wednesday.pcap", "enp0s3-public-wednesday.pcap_Flow.csv", False),
    "wednesday-pvt": ("enp0s3-pvt-wednesday.pcap", "enp0s3-pvt-wednesday.pcap_Flow.csv", False),
    "thursday-pub": ("enp0s3-public-thursday.pcap", "enp0s3-public-thursday.pcap_Flow.csv", False),
    "thursday-pvt": ("enp0s3-pvt-thursday.pcap", "enp0s3-pvt-thursday.pcap_Flow.csv", True),
    "friday-pub": ("enp0s3-tcpdump-friday.pcap", "enp0s3-tcpdump-friday.pcap_Flow.csv", False),
    "friday-pvt": ("enp0s3-tcpdump-pvt-friday.pcap", "enp0s3-tcpdump-pvt-friday.pcap_Flow.csv", False),
}


def norm_benign(s: str) -> str:
    return "BENIGN" if s.strip().upper() in ("BENIGN", "NORMAL") else s.strip()


def parse_local(s: str):
    for fmt in ("%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S"):
        try:
            return datetime.strptime(s.strip(), fmt)
        except ValueError:
            pass
    return None


def pcap_first_epoch(path: Path) -> float:
    with open(path, "rb") as f:
        f.read(24)                       # global header
        rh = f.read(16)                  # first record header
        sec, frac = struct.unpack("<II", rh[:8])   # little-endian d4c3b2a1, usec
        return sec + frac / 1e6


def is_host(ip: str) -> bool:
    return bool(ip) and not any(ip.startswith(p) for p in MCAST_PREFIXES)


def read_csv_flows(csvdir: Path, cap: str):
    """Return list of dict rows with parsed fields for one capture."""
    pf, cf, headerless = CAPS[cap]
    rows = []
    with open(csvdir / cf, "r", encoding="utf-8", errors="replace") as fh:
        r = csv.reader(fh)
        if headerless:
            SI, DI, SP, DP, PR, TI, STG = 1, 3, 2, 4, 5, 6, 84
        else:
            hdr = next(r)
            ix = {n: i for i, n in enumerate(hdr)}
            SI, DI, SP, DP, PR, TI, STG = (ix["Src IP"], ix["Dst IP"], ix["Src Port"],
                                           ix["Dst Port"], ix["Protocol"], ix["Timestamp"], ix["Stage"])
        for row in r:
            if len(row) <= STG:
                continue
            t = parse_local(row[TI])
            if t is None:
                continue
            rows.append({
                "src_ip": row[SI], "dst_ip": row[DI],
                "src_port": _int(row[SP]), "dst_port": _int(row[DP]),
                "proto": _int(row[PR]), "t_local": t,
                "stage": norm_benign(row[STG]),
            })
    return rows


def _int(x):
    try:
        return int(float(x))
    except (ValueError, TypeError):
        return -1


def measure_offset(csvdir: Path, pcapdir: Path):
    """Return (offset_hours_rounded, per-capture measured hours) UTC = local + offset."""
    per = {}
    for cap, (pf, cf, _hl) in CAPS.items():
        rows = read_csv_flows(csvdir, cap)
        if not rows:
            continue
        tmin = min(r["t_local"] for r in rows)
        ep = pcap_first_epoch(pcapdir / pf)
        off = (ep - tmin.replace(tzinfo=timezone.utc).timestamp()) / 3600.0
        per[cap] = off
    vals = list(per.values())
    rounded = round(sum(vals) / len(vals))
    return rounded, per


def to_utc(t_local: datetime, offset_h: int) -> datetime:
    return (t_local + timedelta(hours=offset_h)).replace(tzinfo=timezone.utc)


def windows(times, gap=GAP):
    times = sorted(times)
    out = []
    if not times:
        return out
    s = prev = times[0]
    for t in times[1:]:
        if (t - prev) > gap:
            out.append((s, prev))
            s = t
        prev = t
    out.append((s, prev))
    return out


def derive_rules(csvdir: Path, offset_h: int):
    """Build rule dicts for the clean stages + a fidelity log."""
    rules = []
    log = []
    for cap in CAPS:
        rows = read_csv_flows(csvdir, cap)
        if not rows:
            continue
        # exclusivity per capture: which Src IPs appear ONLY in attack flows
        src_atk, src_ben = Counter(), Counter()
        for r in rows:
            (src_atk if r["stage"] != "BENIGN" else src_ben)[r["src_ip"]] += 1
        excl_src = {ip for ip in src_atk if src_ben.get(ip, 0) == 0 and is_host(ip)}

        for stage in CLEAN_STAGES:
            srows = [r for r in rows if r["stage"] == stage]
            if not srows:
                continue
            # attack flows we can cover with attack-exclusive source IPs
            cov = [r for r in srows if r["src_ip"] in excl_src]
            if not cov:
                log.append((cap, stage, len(srows), 0, "no attack-exclusive src IP"))
                continue
            for (w0, w1) in windows([r["t_local"] for r in cov]):
                wrows = [r for r in cov if w0 <= r["t_local"] <= w1]
                atk = sorted({r["src_ip"] for r in wrows})
                vic = sorted({r["dst_ip"] for r in wrows if is_host(r["dst_ip"])})
                ports = sorted({r["dst_port"] for r in wrows if r["dst_port"] >= 0})
                protos = sorted({r["proto"] for r in wrows if r["proto"] >= 0})
                u0 = to_utc(w0, offset_h) - timedelta(seconds=PAD_S)
                u1 = to_utc(w1, offset_h) + timedelta(seconds=PAD_S)
                rule = {
                    "name": f"{cap} {stage} {u0.strftime('%H%M%S')}",
                    "label": stage,
                    "date": u0.strftime("%Y-%m-%d"),
                    "start_local": u0.strftime("%H:%M:%S"),
                    "end_local": u1.strftime("%H:%M:%S") if u1.date() == u0.date()
                                 else "23:59:59",   # clamp if window crosses UTC midnight
                    "tz": "+00:00",
                    "attackers": atk,
                    "victims": vic,
                    "proto": protos or [6],
                    "directional": True,   # attacker->victim; avoids matching benign return flows
                    "source": "derived from DAPT CSV (attack-exclusive src IP + window)",
                    "_capture": cap,
                }
                if ports and len(ports) <= 12:
                    rule["dst_ports"] = ports
                rules.append(rule)
            log.append((cap, stage, len(srows), len(cov),
                        f"{len(cov)}/{len(srows)} covered by exclusive-src rules"))
    return rules, log


def collect_recon(csvdir: Path, offset_h: int):
    """Every CSV Reconnaissance flow as a 5-tuple + UTC start, for projection."""
    recs = []
    for cap in CAPS:
        for r in read_csv_flows(csvdir, cap):
            if r["stage"] == RECON_STAGE:
                recs.append({
                    "src_ip": r["src_ip"], "dst_ip": r["dst_ip"],
                    "src_port": r["src_port"], "dst_port": r["dst_port"],
                    "proto": r["proto"],
                    "t_start": to_utc(r["t_local"], offset_h).timestamp(),
                    "_capture": cap,
                })
    return pd.DataFrame(recs)


def csv_frame(csvdir: Path, cap: str, offset_h: int) -> pd.DataFrame:
    """One capture's CSV flows as a canonical-ish frame + true Stage (for report)."""
    rows = []
    for r in read_csv_flows(csvdir, cap):
        ts = to_utc(r["t_local"], offset_h).timestamp()
        rows.append({"src_ip": r["src_ip"], "dst_ip": r["dst_ip"],
                     "src_port": r["src_port"], "dst_port": r["dst_port"],
                     "proto": r["proto"], "t_start": ts, "t_end": ts,
                     "true": r["stage"]})
    return pd.DataFrame(rows)


def fidelity_report(csvdir: Path, offset_h: int) -> str:
    """Run the REAL labeling path per capture on the CSV flows and score it
    against DAPT's own Stage labels (upper-bound reconstruction fidelity)."""
    from nids_xstudy.labeling import label_dataset
    parts, proj = [], 0
    for cap in CAPS:
        d = csv_frame(csvdir, cap, offset_h)
        if d.empty:
            continue
        lab = label_dataset(d.copy(), DATASET, cfg, capture=cap)
        d["pred"] = lab["label"].astype(str)
        proj += int(lab.attrs.get("recon_projected", 0))
        parts.append(d)
    df = pd.concat(parts, ignore_index=True)
    stages = ["BENIGN", RECON_STAGE] + CLEAN_STAGES
    lines = ["## Labeling fidelity vs DAPT CSV ground truth",
             f"Applied capture-scoped rules + hybrid recon projection to the "
             f"{len(df):,} CSV flows; recon flows projected: {proj}.", "",
             "| stage | n (true) | precision | recall |", "|---|---:|---:|---:|"]
    for s in stages:
        tp = int(((df["true"] == s) & (df["pred"] == s)).sum())
        fp = int(((df["true"] != s) & (df["pred"] == s)).sum())
        fn = int(((df["true"] == s) & (df["pred"] != s)).sum())
        n = int((df["true"] == s).sum())
        p = tp / (tp + fp) if tp + fp else float("nan")
        rc = tp / (tp + fn) if tp + fn else float("nan")
        lines.append(f"| {s} | {n:,} | {p:.3f} | {rc:.3f} |")
    tb = (df["true"] != "BENIGN"); pb = (df["pred"] != "BENIGN")
    tp = int((tb & pb).sum()); fp = int((~tb & pb).sum()); fn = int((tb & ~pb).sum())
    lines += ["", f"Binary (ATTACK vs BENIGN): precision {tp/(tp+fp):.3f}, "
              f"recall {tp/(tp+fn):.3f} (tp={tp}, fp={fp}, fn={fn}).",
              "", "The fn are tiny-count attack flows with no attack-exclusive "
              "endpoint (left BENIGN); documented as label noise."]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csvdir", default=None, help="override E:/DAPT20/csv")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    pcapdir = cfg.pcap_root(DATASET)
    csvdir = Path(args.csvdir) if args.csvdir else pcapdir.parent / "csv"
    print(f"csvdir={csvdir}  pcapdir={pcapdir}", flush=True)

    offset_h, per = measure_offset(csvdir, pcapdir)
    spread = max(per.values()) - min(per.values())
    print(f"\n== timezone offset (UTC = local + offset) ==")
    for cap, off in per.items():
        print(f"   {cap:16s} {off:+.3f} h")
    print(f"   -> using +{offset_h} h (spread across captures {spread:.3f} h)")
    assert spread < 0.05, "offset inconsistent across captures; investigate before freezing"

    rules, log = derive_rules(csvdir, offset_h)
    recon = collect_recon(csvdir, offset_h)

    print(f"\n== clean-stage rule derivation ==")
    for cap, stage, n, cov, note in log:
        print(f"   {cap:16s} {stage:20s} n={n:6d}  {note}")
    print(f"   emitted {len(rules)} rules across {len({r['_capture'] for r in rules})} captures")
    print(f"\n== reconnaissance (projected, hybrid) ==")
    print(f"   {len(recon)} recon flows dumped for 5-tuple+time projection")

    if args.dry_run:
        print("\n[dry-run] no files written")
        return

    # write rules.yaml
    out_rules = cfg.rules_path(DATASET)
    out_rules.parent.mkdir(parents=True, exist_ok=True)
    _write_rules_yaml(out_rules, rules, offset_h)
    print(f"\nwrote {out_rules}")

    # write recon reference
    out_recon = cfg.labels_dir(DATASET) / "recon_flows.parquet"
    recon.to_parquet(out_recon, index=False)
    print(f"wrote {out_recon} ({len(recon)} flows)")

    # write derivation + fidelity report (reproducible artifact)
    report = [
        "# DAPT2020 label derivation report",
        "",
        f"Generated by scripts/derive_dapt20_rules.py. Timezone offset UTC = "
        f"local + {offset_h} h (Arizona MST; max cross-capture spread {spread:.3f} h).",
        "",
        "## Clean-stage rule coverage (rules engine, attack-exclusive src IPs)",
        "| capture | stage | attack flows | covered |", "|---|---|---:|---:|",
    ]
    for cap, stage, n, cov, _note in log:
        report.append(f"| {cap} | {stage} | {n:,} | {cov:,} |")
    report += ["",
               f"Emitted {len(rules)} capture-scoped rules. Reconnaissance "
               f"({len(recon):,} flows) is projected per-flow (hybrid), not a rule.",
               ""]
    report.append(fidelity_report(csvdir, offset_h))
    out_report = cfg.labels_dir(DATASET) / "derivation_report.md"
    out_report.write_text("\n".join(report), encoding="utf-8")
    print(f"wrote {out_report}")


def _write_rules_yaml(path: Path, rules, offset_h: int):
    lines = [
        "# DAPT2020 labeling rules (DERIVED; see scripts/derive_dapt20_rules.py).",
        "#",
        "# HYBRID labeling (approved): the clean-separable stages below are matched",
        "# by the time+IP+port engine on attack-EXCLUSIVE source IPs. The",
        "# Reconnaissance stage is NOT here -- it is not separable by 5-tuple+time",
        "# and is projected from DAPT's per-flow label (data/labels/dapt20/",
        "# recon_flows.parquet) at label time by nids_xstudy.labeling.dapt_recon.",
        "#",
        f"# Times are UTC (tz +00:00). CSV local time is Arizona MST; measured",
        f"# offset UTC = local + {offset_h} h (verified across all captures).",
        "",
        "dataset: dapt20",
        "benign_label: BENIGN",
        "",
        "timezone:",
        "  capture_tz: America/Phoenix   # Arizona MST, UTC-7, no DST",
        "  windows_tz: UTC",
        f"  note: >",
        f"    Windows in UTC. corrected_UTC = MST_local + {offset_h}. Reconnaissance is",
        "    projected per-flow (hybrid), not a window rule.",
        "",
        "attacks:",
    ]
    for r in rules:
        lines.append(f"  - name: {r['name']!r}")
        lines.append(f"    label: {r['label']!r}")
        lines.append(f"    date: {r['date']}")
        lines.append(f"    start_local: \"{r['start_local']}\"")
        lines.append(f"    end_local:   \"{r['end_local']}\"")
        lines.append(f"    tz: \"{r['tz']}\"")
        lines.append(f"    attackers: [{', '.join(r['attackers'])}]")
        lines.append(f"    victims:   [{', '.join(r['victims'])}]")
        if "dst_ports" in r:
            lines.append(f"    dst_ports: [{', '.join(str(p) for p in r['dst_ports'])}]")
        lines.append(f"    proto: [{', '.join(str(p) for p in r['proto'])}]")
        lines.append(f"    directional: true")
        lines.append(f"    capture: {r['_capture']}")
        lines.append(f"    source: {r['source']!r}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
