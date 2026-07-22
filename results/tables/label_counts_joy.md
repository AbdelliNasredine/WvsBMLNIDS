# CICIDS2017 label validation — joy

Total flows (week): **2,892,129**  |  BENIGN: **2,409,313**  |  attack classes: 14

Ours = outer-window count (this tool's segmentation). Expected = Engelen
WTMC2021 effective (CICFlowMeter-fixed). Ratio≈1 ⇒ agreement; large
deviations are expected for attempted-heavy classes (Web/Bot/Slow*).

| class | ours | expected_effective | ratio |
| --- | --- | --- | --- |
| PortScan | 160101 | 159023 | 1.007 |
| DoS Hulk | 163756 | 158469 | 1.033 |
| DDoS | 108625 | 95123 | 1.142 |
| DoS GoldenEye | 11094 | 7567 | 1.466 |
| DoS slowloris | 14334 | 4001 | 3.583 |
| FTP-Patator | 4003 | 3973 | 1.008 |
| SSH-Patator | 2990 | 2980 | 1.003 |
| DoS Slowhttptest | 13372 | 1742 | 7.676 |
| Bot | 2199 | 738 | 2.98 |
| Web Attack - Brute Force | 1438 | 151 | 9.523 |
| Infiltration | 138 | 32 | 4.312 |
| Web Attack - XSS | 707 | 27 | 26.185 |
| Web Attack - Sql Injection | 18 | 12 | 1.5 |
| Heartbleed | 41 | 11 | 3.727 |

## Per-capture attack labels

**Tuesday**: FTP-Patator=4003, SSH-Patator=2990
**Wednesday**: DoS Hulk=163756, DoS slowloris=14334, DoS Slowhttptest=13372, DoS GoldenEye=11094, Heartbleed=41
**Thursday**: Web Attack - Brute Force=1438, Web Attack - XSS=707, Infiltration=138, Web Attack - Sql Injection=18
**Friday**: PortScan=160101, DDoS=108625, Bot=2199
