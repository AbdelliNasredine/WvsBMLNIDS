"""Traffic-level labeling engine.

Given canonical flows (from *any* tool) and a ``rules.yaml`` describing attack
windows, the engine assigns each flow a multiclass ``label``, a ``binary_label``
(BENIGN/ATTACK) and a ``label_confidence``:

* ``exact``       — flow fully inside an attack window and all IP/port/proto
                    constraints matched;
* ``window_edge`` — flow matched but straddles the window boundary in time
                    (candidate for exclusion in the label-noise sensitivity run);
* ``benign``      — no attack rule matched (benign by exclusion).

Matching is vectorized per rule so it scales to millions of flows.

Directionality: by default IP matching is direction-agnostic (a flow oriented
victim->attacker still matches), because different extractors orient flows
differently. Set ``directional: true`` on a rule to require attacker->victim.
Likewise service ports are matched against either endpoint's port unless the
rule sets ``directional: true``.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd
import yaml

BENIGN = "BENIGN"
ATTACK = "ATTACK"


def _to_epoch(date: str, local_time: str, tz: str) -> float:
    """Convert a local ``date``/``time`` in ``tz`` to a UTC epoch second.

    ``tz`` may be an IANA name (``America/Halifax``) or a fixed offset
    (``-03:00``). IANA names handle DST correctly (CICIDS2017 July capture is
    ADT = UTC-3).
    """
    stamp = f"{date}T{local_time}"
    dt = datetime.fromisoformat(stamp)
    if tz and (tz[0] in "+-") and ":" in tz:
        sign = 1 if tz[0] == "+" else -1
        hh, mm = tz[1:].split(":")
        from datetime import timedelta, timezone
        dt = dt.replace(tzinfo=timezone(sign * timedelta(hours=int(hh), minutes=int(mm))))
    else:
        dt = dt.replace(tzinfo=ZoneInfo(tz))
    return dt.timestamp()


@dataclass
class AttackRule:
    name: str
    label: str
    t_start: float          # UTC epoch
    t_end: float
    attackers: list[str]
    victims: list[str]
    dst_ports: list[int]
    protos: list[int]
    directional: bool
    attacker_cidrs: list[str] = field(default_factory=list)
    victim_cidrs: list[str] = field(default_factory=list)
    source: str = ""
    notes: str = ""

    def resolve_endpoints(self, unique_ips) -> tuple[set[str], set[str]]:
        """Expand explicit IP lists + CIDRs against the IPs present in the data.

        Returns (attacker_ip_set, victim_ip_set). Empty sets mean "unconstrained"
        for that endpoint (handled by the caller).
        """
        atk = set(self.attackers)
        vic = set(self.victims)
        if self.attacker_cidrs:
            atk |= _ips_in_cidrs(unique_ips, self.attacker_cidrs)
        if self.victim_cidrs:
            vic |= _ips_in_cidrs(unique_ips, self.victim_cidrs)
        return atk, vic


def _ips_in_cidrs(unique_ips, cidrs: list[str]) -> set[str]:
    nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
    hit = set()
    for ip in unique_ips:
        if ip is None or (isinstance(ip, float) and pd.isna(ip)):
            continue
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            continue
        if any(addr in n for n in nets):
            hit.add(str(ip))
    return hit


class LabelRules:
    """Parsed rules file with attack windows precomputed to UTC epoch."""

    def __init__(self, spec: dict):
        self.dataset = spec.get("dataset", "unknown")
        self.benign_label = spec.get("benign_label", BENIGN)
        self.default_tz = spec.get("timezone", {}).get("capture_tz", "UTC")
        self.meta = spec.get("timezone", {})
        self.rules: list[AttackRule] = []
        for a in spec.get("attacks", []):
            tz = a.get("tz", self.default_tz)
            self.rules.append(AttackRule(
                name=a["name"],
                label=a.get("label", a["name"]),
                t_start=_to_epoch(a["date"], a["start_local"], tz),
                t_end=_to_epoch(a["date"], a["end_local"], tz),
                attackers=[str(x) for x in a.get("attackers", [])],
                victims=[str(x) for x in a.get("victims", [])],
                dst_ports=[int(x) for x in a.get("dst_ports", [])],
                protos=[int(x) for x in a.get("proto", [])],
                directional=bool(a.get("directional", False)),
                attacker_cidrs=[str(x) for x in a.get("attacker_cidr", [])],
                victim_cidrs=[str(x) for x in a.get("victim_cidr", [])],
                source=a.get("source", ""),
                notes=a.get("notes", ""),
            ))

    @classmethod
    def load(cls, path: Path | str) -> "LabelRules":
        with open(path, "r", encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh))

    def summary(self) -> pd.DataFrame:
        rows = [{
            "name": r.name, "label": r.label,
            "t_start_utc": datetime.utcfromtimestamp(r.t_start).isoformat() + "Z",
            "t_end_utc": datetime.utcfromtimestamp(r.t_end).isoformat() + "Z",
            "attackers": ",".join(r.attackers), "victims": ",".join(r.victims),
            "dst_ports": r.dst_ports, "protos": r.protos, "directional": r.directional,
        } for r in self.rules]
        return pd.DataFrame(rows)


def _rule_mask(df: pd.DataFrame, r: AttackRule, unique_ips) -> tuple[pd.Series, pd.Series]:
    """Return (matched, fully_inside) boolean masks for rule ``r`` over ``df``."""
    src_ip, dst_ip = df["src_ip"], df["dst_ip"]
    src_port, dst_port = df["src_port"], df["dst_port"]

    # temporal overlap of [t_start, t_end] with the attack window
    overlap = (df["t_start"] <= r.t_end) & (df["t_end"] >= r.t_start)
    inside = (df["t_start"] >= r.t_start) & (df["t_end"] <= r.t_end)

    mask = overlap

    atk_set, vic_set = r.resolve_endpoints(unique_ips)
    if atk_set or vic_set:
        true = pd.Series(True, index=df.index)
        atk = src_ip.isin(atk_set) if atk_set else true
        vic = dst_ip.isin(vic_set) if vic_set else true
        fwd = atk & vic
        if r.directional:
            ip_ok = fwd
        else:
            atk_r = dst_ip.isin(atk_set) if atk_set else true
            vic_r = src_ip.isin(vic_set) if vic_set else true
            ip_ok = fwd | (atk_r & vic_r)
        mask = mask & ip_ok

    if r.dst_ports:
        if r.directional:
            port_ok = dst_port.isin(r.dst_ports)
        else:
            port_ok = dst_port.isin(r.dst_ports) | src_port.isin(r.dst_ports)
        mask = mask & port_ok

    if r.protos:
        mask = mask & df["proto"].isin(r.protos)

    return mask.fillna(False), (mask & inside).fillna(False)


def label_flows(df: pd.DataFrame, rules: LabelRules) -> pd.DataFrame:
    """Add ``label``, ``binary_label``, ``label_confidence``, ``n_rule_matches``.

    When a flow matches multiple attack rules, the first rule (file order) wins;
    ``n_rule_matches`` records the count so overlaps can be audited.
    """
    df = df.copy()
    n = len(df)
    label = pd.Series([rules.benign_label] * n, index=df.index, dtype="object")
    conf = pd.Series(["benign"] * n, index=df.index, dtype="object")
    n_matches = pd.Series(0, index=df.index, dtype="int64")
    assigned = pd.Series(False, index=df.index)

    # unique IPs (both endpoints) drive CIDR expansion once per call
    unique_ips = pd.unique(pd.concat([df["src_ip"], df["dst_ip"]], ignore_index=True))

    for r in rules.rules:
        matched, inside = _rule_mask(df, r, unique_ips)
        n_matches = n_matches + matched.astype("int64")
        take = matched & (~assigned)
        label = label.mask(take, r.label)
        conf = conf.mask(take & inside, "exact")
        conf = conf.mask(take & (~inside), "window_edge")
        assigned = assigned | take

    df["label"] = label.astype("string")
    df["binary_label"] = pd.Series(
        [BENIGN if x == rules.benign_label else ATTACK for x in label],
        index=df.index, dtype="string",
    )
    df["label_confidence"] = conf.astype("string")
    df["n_rule_matches"] = n_matches
    return df


def class_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """Per-class flow counts + confidence breakdown for a labeled frame."""
    g = df.groupby("label", dropna=False)
    out = g.size().rename("n_flows").to_frame()
    out["frac"] = out["n_flows"] / out["n_flows"].sum()
    if "label_confidence" in df.columns:
        conf = df.pivot_table(index="label", columns="label_confidence",
                              values="src_ip", aggfunc="count", fill_value=0)
        out = out.join(conf)
    return out.reset_index().sort_values("n_flows", ascending=False)
