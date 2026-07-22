# CICIDS2017 label validation — argus

Total flows (week): **1,343,699**  |  BENIGN: **1,113,501**  |  attack classes: 14

Ours = outer-window count (this tool's segmentation). Expected = Engelen
WTMC2021 effective (CICFlowMeter-fixed). Ratio≈1 ⇒ agreement; large
deviations are expected for attempted-heavy classes (Web/Bot/Slow*).

| class | ours | expected_effective | ratio |
| --- | --- | --- | --- |
| PortScan | 159678 | 159023 | 1.004 |
| DoS Hulk | 6004 | 158469 | 0.038 |
| DDoS | 45206 | 95123 | 0.475 |
| DoS GoldenEye | 0 | 7567 | 0.0 |
| DoS slowloris | 3895 | 4001 | 0.974 |
| FTP-Patator | 3992 | 3973 | 1.005 |
| SSH-Patator | 2979 | 2980 | 1.0 |
| DoS Slowhttptest | 4217 | 1742 | 2.421 |
| Bot | 2192 | 738 | 2.97 |
| Web Attack - Brute Force | 1365 | 151 | 9.04 |
| Infiltration | 32 | 32 | 1.0 |
| Web Attack - XSS | 620 | 27 | 22.963 |
| Web Attack - Sql Injection | 17 | 12 | 1.417 |
| Heartbleed | 1 | 11 | 0.091 |

## Per-capture attack labels

**Tuesday**: FTP-Patator=3992, SSH-Patator=2979
**Wednesday**: DoS Hulk=6004, DoS Slowhttptest=4217, DoS slowloris=3895, Heartbleed=1
**Thursday**: Web Attack - Brute Force=1365, Web Attack - XSS=620, Infiltration=32, Web Attack - Sql Injection=17
**Friday**: PortScan=159678, DDoS=45206, Bot=2192
