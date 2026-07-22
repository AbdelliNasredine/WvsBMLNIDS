# CICIDS2017 label validation — nfstream

Total flows (week): **1,845,604**  |  BENIGN: **1,579,826**  |  attack classes: 14

Ours = outer-window count (this tool's segmentation). Expected = Engelen
WTMC2021 effective (CICFlowMeter-fixed). Ratio≈1 ⇒ agreement; large
deviations are expected for attempted-heavy classes (Web/Bot/Slow*).

| class | ours | expected_effective | ratio |
| --- | --- | --- | --- |
| PortScan | 159857 | 159023 | 1.005 |
| DoS Hulk | 14437 | 158469 | 0.091 |
| DDoS | 63540 | 95123 | 0.668 |
| DoS GoldenEye | 7656 | 7567 | 1.012 |
| DoS slowloris | 4515 | 4001 | 1.128 |
| FTP-Patator | 4003 | 3973 | 1.008 |
| SSH-Patator | 2980 | 2980 | 1.0 |
| DoS Slowhttptest | 4496 | 1742 | 2.581 |
| Bot | 2199 | 738 | 2.98 |
| Web Attack - Brute Force | 1367 | 151 | 9.053 |
| Infiltration | 36 | 32 | 1.125 |
| Web Attack - XSS | 673 | 27 | 24.926 |
| Web Attack - Sql Injection | 18 | 12 | 1.5 |
| Heartbleed | 1 | 11 | 0.091 |

## Per-capture attack labels

**Tuesday**: FTP-Patator=4003, SSH-Patator=2980
**Wednesday**: DoS Hulk=14437, DoS GoldenEye=7656, DoS slowloris=4515, DoS Slowhttptest=4496, Heartbleed=1
**Thursday**: Web Attack - Brute Force=1367, Web Attack - XSS=673, Infiltration=36, Web Attack - Sql Injection=18
**Friday**: PortScan=159857, DDoS=63540, Bot=2199
