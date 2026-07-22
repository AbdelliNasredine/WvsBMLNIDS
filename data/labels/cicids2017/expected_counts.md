# CICIDS2017 — expected corrected flow counts (Phase-1 sanity check)

Use these to validate our re-extracted + re-labeled flow counts. Our
time-window labeling produces the **outer-bound** count (effective + attempted +
some benign spillover); the *effective* column is the target after the
attempted/payload filter (Phase-4 label-noise pass). Exact agreement is not
expected — the point is order-of-magnitude agreement and correct ranking.

Source: Engelen, Rimmer, Joosen, WTMC 2021, Table I (read from PDF). Liu et al.
CNS 2022 report identical effective attack counts with a lower benign total
(1,657,069) from a later re-generation pipeline.

| Class | Original | Intermediate (TCP-fixed) | **Effective (Final)** | Attempted (removed) |
|---|---:|---:|---:|---:|
| BENIGN | 2,271,326 | 1,823,964 | 1,823,964 | — |
| FTP-Patator | 7,934 | 3,984 | **3,973** | 11 |
| SSH-Patator | 5,898 | 2,988 | **2,980** | 8 |
| DoS GoldenEye | 10,293 | 7,647 | **7,567** | 80 |
| DoS Hulk | 230,124 | 159,048 | **158,469** | 579 |
| DoS Slowhttptest | 5,499 | 5,109 | **1,742** | 3,367 |
| DoS slowloris | 5,791 | 5,707 | **4,001** | 1,706 |
| Heartbleed | 11 | 11 | **11** | 0 |
| Web Attack - Brute Force | 1,507 | 1,365 | **151** | 1,214 |
| Web Attack - XSS | 652 | 679 | **27** | 652 |
| Web Attack - Sql Injection | 21 | 12 | **12** | 0 |
| Infiltration | 36 | 48 | **32** | 16 |
| Bot | 1,956 | 2,208 | **738** | 1,470 |
| PortScan | 158,842 | 159,023 | **159,023** | — |
| DDoS | 128,022 | 95,123 | **95,123** | 0 |

Total attempted removed = **9,103** (sum of Intermediate→Final deltas).

Notes:
- Benign totals differ by pipeline version (Engelen 1,823,964 vs Liu 1,657,069) —
  a version difference, not a contradiction.
- Heartbleed is the cleanest check: exactly **11 flows**, victim
  `192.168.10.51:444`, 18:12:15–18:32:43 UTC. If our extractor finds ~11 flows
  in that window, timezone + IP + port handling is correct.
- The lumped `ATTEMPTED* = 447,362` row in Engelen Table I is an aggregation
  artifact/typo — do not use it.
