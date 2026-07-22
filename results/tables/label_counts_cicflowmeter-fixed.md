# CICIDS2017 label validation — cicflowmeter-fixed

Total flows (week): **2,104,266**  |  BENIGN: **1,656,781**  |  attack classes: 14

Ours = outer-window count (this tool's segmentation). Expected = Engelen
WTMC2021 effective (CICFlowMeter-fixed). Ratio≈1 ⇒ agreement; large
deviations are expected for attempted-heavy classes (Web/Bot/Slow*).

| class | ours | expected_effective | ratio |
| --- | --- | --- | --- |
| PortScan | 160100 | 159023 | 1.007 |
| DoS Hulk | 159138 | 158469 | 1.004 |
| DDoS | 95683 | 95123 | 1.006 |
| DoS GoldenEye | 7780 | 7567 | 1.028 |
| DoS slowloris | 5731 | 4001 | 1.432 |
| FTP-Patator | 4003 | 3973 | 1.008 |
| SSH-Patator | 2988 | 2980 | 1.003 |
| DoS Slowhttptest | 5112 | 1742 | 2.935 |
| Bot | 4803 | 738 | 6.508 |
| Web Attack - Brute Force | 1367 | 151 | 9.053 |
| Infiltration | 78 | 32 | 2.438 |
| Web Attack - XSS | 673 | 27 | 24.926 |
| Web Attack - Sql Injection | 18 | 12 | 1.5 |
| Heartbleed | 11 | 11 | 1.0 |

## Per-capture attack labels

**Tuesday**: FTP-Patator=4003, SSH-Patator=2988
**Wednesday**: DoS Hulk=159138, DoS GoldenEye=7780, DoS slowloris=5731, DoS Slowhttptest=5112, Heartbleed=11
**Thursday**: Web Attack - Brute Force=1367, Web Attack - XSS=673, Infiltration=78, Web Attack - Sql Injection=18
**Friday**: PortScan=160100, DDoS=95683, Bot=4803
