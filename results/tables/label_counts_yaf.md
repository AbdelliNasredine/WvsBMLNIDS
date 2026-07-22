# CICIDS2017 label validation — yaf

Total flows (week): **2,315,846**  |  BENIGN: **1,732,809**  |  attack classes: 14

Ours = outer-window count (this tool's segmentation). Expected = Engelen
WTMC2021 effective (CICFlowMeter-fixed). Ratio≈1 ⇒ agreement; large
deviations are expected for attempted-heavy classes (Web/Bot/Slow*).

| class | ours | expected_effective | ratio |
| --- | --- | --- | --- |
| PortScan | 160891 | 159023 | 1.012 |
| DoS Hulk | 292978 | 158469 | 1.849 |
| DDoS | 95241 | 95123 | 1.001 |
| DoS GoldenEye | 7574 | 7567 | 1.001 |
| DoS slowloris | 3897 | 4001 | 0.974 |
| FTP-Patator | 8036 | 3973 | 2.023 |
| SSH-Patator | 3013 | 2980 | 1.011 |
| DoS Slowhttptest | 4494 | 1742 | 2.58 |
| Bot | 4803 | 738 | 6.508 |
| Web Attack - Brute Force | 1368 | 151 | 9.06 |
| Infiltration | 49 | 32 | 1.531 |
| Web Attack - XSS | 673 | 27 | 24.926 |
| Web Attack - Sql Injection | 19 | 12 | 1.583 |
| Heartbleed | 1 | 11 | 0.091 |

## Per-capture attack labels

**Tuesday**: FTP-Patator=8036, SSH-Patator=3013
**Wednesday**: DoS Hulk=292978, DoS GoldenEye=7574, DoS Slowhttptest=4494, DoS slowloris=3897, Heartbleed=1
**Thursday**: Web Attack - Brute Force=1368, Web Attack - XSS=673, Infiltration=49, Web Attack - Sql Injection=19
**Friday**: PortScan=160891, DDoS=95241, Bot=4803
