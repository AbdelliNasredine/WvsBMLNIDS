# CICIDS2017 label validation — tranalyzer

Total flows (week): **2,013,868**  |  BENIGN: **1,569,277**  |  attack classes: 14

Ours = outer-window count (this tool's segmentation). Expected = Engelen
WTMC2021 effective (CICFlowMeter-fixed). Ratio≈1 ⇒ agreement; large
deviations are expected for attempted-heavy classes (Web/Bot/Slow*).

| class | ours | expected_effective | ratio |
| --- | --- | --- | --- |
| PortScan | 160101 | 159023 | 1.007 |
| DoS Hulk | 159322 | 158469 | 1.005 |
| DDoS | 95683 | 95123 | 1.006 |
| DoS GoldenEye | 7496 | 7567 | 0.991 |
| DoS slowloris | 3895 | 4001 | 0.974 |
| FTP-Patator | 3992 | 3973 | 1.005 |
| SSH-Patator | 2980 | 2980 | 1.0 |
| DoS Slowhttptest | 4217 | 1742 | 2.421 |
| Bot | 4803 | 738 | 6.508 |
| Web Attack - Brute Force | 1367 | 151 | 9.053 |
| Infiltration | 43 | 32 | 1.344 |
| Web Attack - XSS | 673 | 27 | 24.926 |
| Web Attack - Sql Injection | 18 | 12 | 1.5 |
| Heartbleed | 1 | 11 | 0.091 |

## Per-capture attack labels

**Tuesday**: FTP-Patator=3992, SSH-Patator=2980
**Wednesday**: DoS Hulk=159322, DoS GoldenEye=7496, DoS Slowhttptest=4217, DoS slowloris=3895, Heartbleed=1
**Thursday**: Web Attack - Brute Force=1367, Web Attack - XSS=673, Infiltration=43, Web Attack - Sql Injection=18
**Friday**: PortScan=160101, DDoS=95683, Bot=4803
