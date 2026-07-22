# Experimental Plan — Impact of White-Box Feature Extraction on ML-Based NIDS Performance

**Purpose of this document.** This is the master plan for an empirical study measuring how the choice of network-traffic feature extractor (Zeek, CICFlowMeter, NFStream, Argus, Tranalyzer) affects the measured performance of ML-based Network Intrusion Detection Systems. It is written to be executed with Claude Code: each phase is decomposed into concrete tasks with inputs, outputs, acceptance criteria, and pitfalls. Follow phases in order; each phase gates the next.

---

## 1. Research Questions and Hypotheses

- **RQ1 (Tool-induced variance):** Given identical raw traffic (PCAPs) and identical ground-truth attack annotations, how much does ML-NIDS detection performance (macro-F1, per-class recall, FPR) vary solely as a function of the feature extraction tool?
- **RQ2 (Feature set vs. implementation):** How much of the observed variance is attributable to (a) *different feature sets* across tools vs. (b) *different implementations of nominally identical features* (e.g., flow duration, packet counts, TCP flag counts computed differently)?
- **RQ3 (Flow accounting divergence):** Do tools even agree on the *unit of analysis*? Quantify divergence in flow counts, flow boundaries (timeout/termination logic), and directionality for the same PCAP.
- **RQ4 (Bug impact):** What is the measurable performance delta between buggy and corrected extractor versions (original CICFlowMeter vs. the fixed DistriNet/Engelen variant)?
- **RQ5 (Generalization):** Does the extractor choice change *cross-dataset* generalization conclusions (train on dataset A, test on dataset B), i.e., could prior generalization findings be extractor artifacts?

**Hypotheses:**
- **H1:** Extractor choice induces performance differences comparable in magnitude to model choice (expected ≥ 3–10 macro-F1 points on some classes).
- **H2:** A large fraction of variance persists even on a harmonized common feature subset → implementation semantics matter, not just feature richness.
- **H3:** Tools disagree substantially on flow segmentation (>10% flow count divergence), especially for long-lived and abnormal (attack) connections — precisely the traffic that matters.
- **H4:** Rankings of ML models (e.g., RF vs. XGBoost vs. MLP) are *not stable* across extractors, undermining tool-agnostic model comparisons in the literature.

---

## 2. Scope and Design Overview

**Independent variables:**
1. Feature extractor: {CICFlowMeter v4 (original), CICFlowMeter-fixed (DistriNet fork by Engelen et al.), NFStream, Zeek (conn.log + custom statistical script), Argus, Tranalyzer2}. Minimum viable set if time-constrained: {CICFlowMeter original, CICFlowMeter fixed, NFStream, Zeek}.
2. Feature space regime: {native full feature set per tool, harmonized common feature set (~15–20 features mappable across all tools, aligned with the Sarhan et al. NetFlow feature standardization spirit)}.
3. ML model: {Random Forest, XGBoost, MLP, Logistic Regression (linear baseline)}.
4. Dataset: {CICIDS2017 (with corrected labels), UNSW-NB15}; optional extension: CSE-CIC-IDS2018 subset, ToN_IoT.

**Dependent variables:** macro-F1, per-class precision/recall/F1, balanced accuracy, FPR at fixed TPR, AUC-PR; flow-accounting agreement metrics (Section 6).

**Controls:** identical PCAP inputs, identical ground-truth labeling rules applied at the flow level, identical train/test split policy (temporal split by capture day), identical hyperparameter budget per model, fixed seeds × 5 repetitions.

**Design principle:** the ONLY thing that changes between conditions in RQ1/RQ2 is the extractor. Everything downstream (labeling logic, splits, preprocessing, models, metrics) is a single shared pipeline.

---

## 3. Repository Layout

```
nids-extractor-study/
├── EXPERIMENT_PLAN.md              # this file
├── env/
│   ├── docker/                     # one Dockerfile per extractor (version-pinned)
│   │   ├── cicflowmeter-orig/
│   │   ├── cicflowmeter-fixed/
│   │   ├── nfstream/
│   │   ├── zeek/
│   │   ├── argus/
│   │   └── tranalyzer/
│   └── requirements.txt            # pinned Python env for ML pipeline
├── data/
│   ├── raw/                        # PCAPs (not committed; download scripts only)
│   ├── extracted/<dataset>/<tool>/ # raw tool output (CSV / conn.log / etc.)
│   ├── canonical/<dataset>/<tool>/ # normalized parquet: one row per flow, canonical schema
│   └── labels/<dataset>/           # ground-truth rules (YAML) + labeled flow keys
├── src/
│   ├── extraction/                 # per-tool runner + output parser → canonical schema
│   ├── labeling/                   # timestamp/IP/port rule engine, one implementation
│   ├── harmonize/                  # common-feature mapping tables per tool
│   ├── flow_alignment/             # cross-tool flow matching & divergence metrics
│   ├── ml/                         # datasets, splits, models, training, eval
│   └── analysis/                   # stats tests, tables, figures
├── configs/                        # YAML per experiment (tool × dataset × regime × model)
├── results/
│   ├── metrics/                    # one JSON per run
│   ├── tables/                     # generated LaTeX/markdown tables
│   └── figures/
└── scripts/                        # orchestration entrypoints (make-style)
```

**Rule for Claude Code:** every experiment run is fully specified by a config file; every result JSON embeds the config hash, git commit, tool version, and seed. No un-versioned results.

---

## 4. Phase 0 — Environment and Tooling (gate: all extractors run on a test PCAP)

**Tasks:**
1. Build one Docker image per extractor with pinned versions:
   - CICFlowMeter original: Java v4.0 (the version used to generate CICIDS2017 features).
   - CICFlowMeter fixed: the DistriNet/CICFlowMeter fork (Engelen, Rimmer, Joosen corrections: TCP flag counting, flow termination on FIN/RST, duplicate-flow and timeout handling).
   - NFStream: latest stable (pin exact version), statistical + post-mortem features enabled.
   - Zeek: latest LTS; enable `conn.log` plus a custom script emitting per-connection statistical features (packet/byte counts per direction, duration, inter-arrival summary stats where feasible).
   - Argus: argus + ra clients; bidirectional flow mode.
   - Tranalyzer2: core + basicFlow, basicStats, tcpFlags, pktSIATHisto plugins.
2. Create a 5-minute synthetic test PCAP (tcpreplay/scapy: HTTP, DNS, a long TCP session crossing timeout, a SYN scan burst, a RST-terminated flow) as a smoke-test fixture.
3. Write `src/extraction/run_<tool>.py` wrappers: input PCAP → raw output → parsed canonical parquet.

**Canonical schema (minimum):** `flow_key (src_ip, src_port, dst_ip, dst_port, proto), t_start, t_end, duration, pkts_fwd, pkts_bwd, bytes_fwd, bytes_bwd, tcp_flags_fwd/bwd (per-flag counts where available), tool_native_features (wide columns, prefixed tool_)`.

**Acceptance criteria:**
- All 6 tools process the smoke PCAP without error; parsers produce valid parquet.
- A unit test asserts known ground truths on the synthetic PCAP (e.g., the SYN scan produces N single-packet flows; the RST flow's flag counts are correct per tool's own semantics).
- Document each tool's flow timeout defaults and set an *aligned configuration* where possible (e.g., 120 s idle timeout everywhere it is configurable) AND record the native-default configuration — both will be evaluated (timeout ablation, Section 8).

**Pitfalls:** CICFlowMeter original has known dependency on jnetpcap (build friction — containerize once); Zeek splits what other tools call one flow into multiple connection entries differently; Argus default is unidirectional unless configured; timestamp timezone handling differs (CICIDS2017 PCAPs are in ADT — normalize everything to UTC epoch at parse time).

---

## 5. Phase 1 — Data Acquisition and Ground-Truth Labeling (gate: labeled canonical flows per tool per dataset)

**Datasets (raw PCAPs required — this study re-extracts everything):**
1. **CICIDS2017** — PCAPs from UNB (Mon–Fri capture days). Use *corrected* labeling: encode the attack windows/IP rules from Engelen et al. ("Troubleshooting an Intrusion Detection Dataset") and cross-check against the Liu et al. and Lanvin et al. corrections (payload-less attack flows, mislabeled benign, Tuesday/Thursday issues). Deliverable: `data/labels/cicids2017/rules.yaml` with per-attack (day, time-window UTC, attacker IPs, victim IPs/ports, label, known-caveat notes).
2. **UNSW-NB15** — raw PCAPs + ground-truth CSV (attack start/end times, IPs) from UNSW. Note documented caveats (overlapping benign/attack from same hosts).
3. *(Optional, stretch)* CSE-CIC-IDS2018 (very large — one or two selected days only), ToN_IoT network PCAPs.

**Labeling engine (single shared implementation):**
- Input: canonical flows (any tool) + `rules.yaml`.
- Match on (time overlap with attack window) ∧ (IP pair match) ∧ (port/proto constraints where specified).
- **Critical design decision:** the label is a property of the *traffic*, applied identically to every tool's flow output — never reuse tool-shipped labels. This is the core of internal validity.
- Emit label + `label_confidence` (exact rule hit vs. window-edge overlap) so ambiguous edge flows can be excluded in a sensitivity analysis.

**Acceptance criteria:**
- Per dataset per tool: labeled flow table with class distribution report.
- Sanity check vs. published corrected numbers: CICIDS2017 attack flow counts per class from the fixed CICFlowMeter should approximately match Engelen et al.'s reported counts (document any deviation and cause).
- Cross-tool label consistency report: for matched flows (Phase 2), label agreement should be >99%; disagreements must be explainable by flow-boundary divergence, not labeling bugs.

**Pitfalls:** timezone off-by-3h errors are the classic CICIDS2017 labeling failure; attacks that generate asymmetric traffic may be visible in one direction only for unidirectional tools; DoS/DDoS windows contain interleaved benign traffic from victim hosts — rules must constrain both endpoints where the literature specifies.

---

## 6. Phase 2 — Flow Accounting Divergence Analysis (RQ3; gate: alignment tables + divergence report)

Before any ML, quantify how much the tools disagree about what a "flow" is.

**Tasks:**
1. **Flow matching:** match flows across tools by 5-tuple + temporal overlap (IoU on [t_start, t_end]). Categories: 1:1 match, 1:N split (one tool's flow = many of another's), N:1 merge, unmatched.
2. **Metrics:** per dataset, per tool pair: flow count ratio; % 1:1 matched; split/merge rates; separately for benign vs. each attack class (hypothesis H3: attack traffic diverges more).
3. **Feature-value divergence on 1:1 matched flows:** for nominally identical features (duration, fwd/bwd packets, fwd/bwd bytes, TCP flag counts): relative error distributions, Kolmogorov–Smirnov statistics between per-tool distributions, and a table of systematic discrepancies with root-cause notes (e.g., "CICFlowMeter-orig counts FIN in both directions into fwd counter").
4. Deep-dive case studies: 5 hand-analyzed example flows (one per major discrepancy type) verified against the PCAP in Wireshark/tshark — these become a paper figure/table.

**Acceptance criteria:** a divergence report (`results/tables/flow_divergence.md`) + figures (heatmap of pairwise flow-count agreement; per-class split/merge rates; feature relative-error violin plots).

---

## 7. Phase 3 — ML Pipeline (RQ1, RQ2, RQ4)

**Shared preprocessing (identical for all conditions):**
- Drop identifier features (IPs, ports optional-ablation, timestamps) to avoid shortcut learning; document exactly what is dropped.
- Median imputation for missing values, quantile clipping (1st/99th pct) for heavy-tailed features, standardization fit on train only.
- Temporal split: for CICIDS2017 train on {Mon–Wed}, test on {Thu–Fri} for cross-day evaluation AND a within-day stratified split as the "standard-practice" comparison (report both; the delta is itself a finding). For UNSW-NB15 use the capture-time split.
- 5 seeds; report mean ± std.

**Feature regimes:**
- **R-native:** each tool's full native feature vector (this is what practitioners actually get).
- **R-common:** harmonized common subset. Build `src/harmonize/mapping.yaml`: for each common feature, the exact source column and any unit conversion per tool (e.g., duration µs→s). Target ~15–20 features: duration, pkts/bytes per direction, mean/std/min/max packet size per direction where available, mean IAT, TCP flag counts (SYN, FIN, RST, PSH, ACK), proto, dst_port (ablation). Any feature not cleanly mappable in ≥5 tools is excluded — document exclusions.

**Models & budget:** RF (sklearn), XGBoost, MLP (2–3 hidden layers), Logistic Regression. Identical hyperparameter search budget per model per condition (randomized search, 30 configs, validation split from train). Class weighting for imbalance; no test-set-informed resampling.

**Tasks (binary + multiclass):**
1. Binary attack/benign and multiclass per dataset.
2. Grid: {6 tools} × {2 regimes} × {4 models} × {2 datasets} × {5 seeds} — ~480 training runs for the core grid; each run cheap on tabular data. Prune to the minimum-viable 4 tools if compute-bound.
3. **RQ4 focus pair:** CICFlowMeter-orig vs CICFlowMeter-fixed under identical everything → per-class delta table (the "bug impact" headline result).
4. **Cross-tool transfer (RQ2 sharpening):** train on tool A's R-common features, test on tool B's R-common features (same dataset, same split). A performance drop here isolates *implementation semantics* since the feature schema is identical.

**Acceptance criteria:** every run emits `results/metrics/<hash>.json` (config, seed, per-class metrics, confusion matrix, feature importances for tree models). An aggregation script produces the master results table.

---

## 8. Phase 4 — Ablations and Robustness

1. **Timeout ablation:** re-run NFStream and both CICFlowMeters with idle timeout ∈ {15 s, 60 s, 120 s, 600 s} on one dataset → performance sensitivity curve (isolates flow-segmentation policy from tool identity).
2. **Directionality ablation:** Argus uni- vs bidirectional.
3. **Port feature ablation:** with/without dst_port in R-common (shortcut-learning check).
4. **Label-noise sensitivity:** exclude `label_confidence < exact` flows; re-run core grid on one dataset.
5. **Model ranking stability (H4):** Kendall's τ of model rankings across tools.
6. **RQ5 cross-dataset:** train CICIDS2017 → test UNSW-NB15 (and reverse) on R-common, per tool; does the generalization gap vary by extractor?

---

## 9. Phase 5 — Statistical Analysis and Reporting

1. **Significance testing:** Friedman test over tools (per model×dataset×regime), Nemenyi post-hoc with critical-difference diagrams; Wilcoxon signed-rank for the orig-vs-fixed CICFlowMeter pair; report effect sizes, not just p-values.
2. **Variance decomposition:** simple ANOVA-style decomposition of macro-F1 variance into tool / model / regime / seed components — a single headline figure: "extractor explains X% of performance variance vs Y% for model choice."
3. **Tables (LaTeX-ready):** master results; bug-impact delta; flow divergence; transfer matrix; timeout sensitivity.
4. **Figures:** critical-difference diagram; variance-decomposition bar; per-class F1 heatmap (tool × class); flow-count agreement heatmap; feature relative-error violins; cross-tool transfer matrix heatmap.
5. **Reproducibility package:** Dockerfiles, configs, seeds, download scripts, one `make reproduce` entrypoint; results JSONs archived.

---

## 10. Execution Order for Claude Code (task queue)

| # | Task | Depends on | Est. effort |
|---|------|-----------|-------------|
| 1 | Repo scaffold + pinned envs + Dockerfiles | — | S |
| 2 | Synthetic smoke PCAP + per-tool runners/parsers + unit tests | 1 | M |
| 3 | Timeout/config alignment doc per tool | 2 | S |
| 4 | Dataset download scripts + integrity checks (hashes) | 1 | S |
| 5 | Labeling rules YAML (CICIDS2017 corrected, UNSW-NB15) + rule engine + tests | 2,4 | M |
| 6 | Full extraction runs (all tools × datasets) | 3,5 | L (compute) |
| 7 | Flow alignment + divergence analysis + report | 6 | M |
| 8 | Harmonization mapping + R-common builder + validation | 6 | M |
| 9 | ML pipeline (splits, preprocessing, models, HPO, metrics) | 6 | M |
| 10 | Core grid runs + orig-vs-fixed pair + transfer matrix | 8,9 | L (compute) |
| 11 | Ablations (timeout, directionality, port, label noise) | 10 | M |
| 12 | Stats, tables, figures, variance decomposition | 10,11 | M |
| 13 | Reproducibility package + results write-up draft | 12 | M |

**Compute notes:** CICIDS2017 PCAPs ≈ 50 GB; CSE-CIC-IDS2018 ≈ 500 GB (why it is optional). Extraction is the bottleneck (hours per tool per dataset; parallelize per capture day). ML on tabular flows is cheap (CPU fine; XGBoost/RF minutes per run at CICIDS2017 scale ~2–3 M flows; subsample benign to ≤1 M with documented ratio if needed — same subsample flow keys across tools where matched).

---

## 11. Threats to Validity (address explicitly in the paper)

- **Construct:** "same feature" across tools is our harmonization mapping — publish the mapping and validate on synthetic PCAP ground truth.
- **Internal:** labeling is shared and traffic-level, but flow-boundary divergence means the *populations* differ per tool; report both matched-flows-only and full-population results.
- **External:** two (to four) datasets, all lab-generated benchmarks; findings characterize benchmark methodology, not deployment performance — frame accordingly.
- **Version validity:** all tool versions pinned and reported; CICFlowMeter-orig deliberately included as the historically-used artifact.

## 12. Mapping Results → Paper Sections

- RQ3 divergence report → "Do tools agree on what a flow is?" (motivating section).
- RQ4 orig-vs-fixed deltas → "Bug impact" (connects to Engelen et al. line of work, extends it with cross-model quantification).
- RQ1/RQ2 grid + variance decomposition → main results.
- Transfer matrix + RQ5 → "Implications for reproducibility and generalization claims."
- Ablations → robustness section; harmonization mapping + Docker images → artifact/appendix.