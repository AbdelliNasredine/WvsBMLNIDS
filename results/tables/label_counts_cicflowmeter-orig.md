# CICIDS2017 label validation — cicflowmeter-orig

Total flows (week): **2,723,242**  |  BENIGN: **1,946,290**  |  attack classes: 14

Ours = outer-window count (this tool's segmentation). Expected = Engelen
WTMC2021 effective (CICFlowMeter-fixed). Ratio≈1 ⇒ agreement; large
deviations are expected for attempted-heavy classes (Web/Bot/Slow*).

| class | ours | expected_effective | ratio |
| --- | --- | --- | --- |
| PortScan | 160024 | 159023 | 1.006 |
| DoS Hulk | 381811 | 158469 | 2.409 |
| DDoS | 190259 | 95123 | 2.0 |
| DoS GoldenEye | 10490 | 7567 | 1.386 |
| DoS slowloris | 5725 | 4001 | 1.431 |
| FTP-Patator | 10456 | 3973 | 2.632 |
| SSH-Patator | 5954 | 2980 | 1.998 |
| DoS Slowhttptest | 5104 | 1742 | 2.93 |
| Bot | 4802 | 738 | 6.507 |
| Web Attack - Brute Force | 1512 | 151 | 10.013 |
| Infiltration | 81 | 32 | 2.531 |
| Web Attack - XSS | 693 | 27 | 25.667 |
| Web Attack - Sql Injection | 30 | 12 | 2.5 |
| Heartbleed | 11 | 11 | 1.0 |

## Per-capture attack labels

**Tuesday**: FTP-Patator=10456, SSH-Patator=5954
**Wednesday**: DoS Hulk=381811, DoS GoldenEye=10490, DoS slowloris=5725, DoS Slowhttptest=5104, Heartbleed=11
**Thursday**: Web Attack - Brute Force=1512, Web Attack - XSS=693, Infiltration=81, Web Attack - Sql Injection=30
**Friday**: DDoS=190259, PortScan=160024, Bot=4802
