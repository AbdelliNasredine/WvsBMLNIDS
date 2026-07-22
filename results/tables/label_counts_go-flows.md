# CICIDS2017 label validation — go-flows

Total flows (week): **2,385,692**  |  BENIGN: **1,799,989**  |  attack classes: 14

Ours = outer-window count (this tool's segmentation). Expected = Engelen
WTMC2021 effective (CICFlowMeter-fixed). Ratio≈1 ⇒ agreement; large
deviations are expected for attempted-heavy classes (Web/Bot/Slow*).

| class | ours | expected_effective | ratio |
| --- | --- | --- | --- |
| PortScan | 160929 | 159023 | 1.012 |
| DoS Hulk | 294399 | 158469 | 1.858 |
| DDoS | 95732 | 95123 | 1.006 |
| DoS GoldenEye | 7656 | 7567 | 1.012 |
| DoS slowloris | 4515 | 4001 | 1.128 |
| FTP-Patator | 8049 | 3973 | 2.026 |
| SSH-Patator | 3013 | 2980 | 1.011 |
| DoS Slowhttptest | 4496 | 1742 | 2.581 |
| Bot | 4803 | 738 | 6.508 |
| Web Attack - Brute Force | 1368 | 151 | 9.06 |
| Infiltration | 50 | 32 | 1.562 |
| Web Attack - XSS | 673 | 27 | 24.926 |
| Web Attack - Sql Injection | 19 | 12 | 1.583 |
| Heartbleed | 1 | 11 | 0.091 |

## Per-capture attack labels

**Tuesday**: FTP-Patator=8049, SSH-Patator=3013
**Wednesday**: DoS Hulk=294399, DoS GoldenEye=7656, DoS slowloris=4515, DoS Slowhttptest=4496, Heartbleed=1
**Thursday**: Web Attack - Brute Force=1368, Web Attack - XSS=673, Infiltration=50, Web Attack - Sql Injection=19
**Friday**: PortScan=160929, DDoS=95732, Bot=4803
