# CICIDS2017 label validation — zeek

Total flows (week): **2,119,180**  |  BENIGN: **1,657,370**  |  attack classes: 14

Ours = outer-window count (this tool's segmentation). Expected = Engelen
WTMC2021 effective (CICFlowMeter-fixed). Ratio≈1 ⇒ agreement; large
deviations are expected for attempted-heavy classes (Web/Bot/Slow*).

| class | ours | expected_effective | ratio |
| --- | --- | --- | --- |
| PortScan | 160929 | 159023 | 1.012 |
| DoS Hulk | 163452 | 158469 | 1.031 |
| DDoS | 95683 | 95123 | 1.006 |
| DoS GoldenEye | 7739 | 7567 | 1.023 |
| DoS slowloris | 3902 | 4001 | 0.975 |
| FTP-Patator | 3992 | 3973 | 1.005 |
| SSH-Patator | 2979 | 2980 | 1.0 |
| DoS Slowhttptest | 16062 | 1742 | 9.22 |
| Bot | 4964 | 738 | 6.726 |
| Web Attack - Brute Force | 1367 | 151 | 9.053 |
| Infiltration | 49 | 32 | 1.531 |
| Web Attack - XSS | 673 | 27 | 24.926 |
| Web Attack - Sql Injection | 18 | 12 | 1.5 |
| Heartbleed | 1 | 11 | 0.091 |

## Per-capture attack labels

**Tuesday**: FTP-Patator=3992, SSH-Patator=2979
**Wednesday**: DoS Hulk=163452, DoS Slowhttptest=16062, DoS GoldenEye=7739, DoS slowloris=3902, Heartbleed=1
**Thursday**: Web Attack - Brute Force=1367, Web Attack - XSS=673, Infiltration=49, Web Attack - Sql Injection=18
**Friday**: PortScan=160929, DDoS=95683, Bot=4964
