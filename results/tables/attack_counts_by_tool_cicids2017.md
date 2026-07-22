# CICIDS2017 attack-flow counts by extractor

Flows per class per tool (summed over the captures each tool has
labeled so far). Divergence across columns is the RQ3/RQ4 signal —
note e.g. DoS Hulk (NFStream merges; others match CICFlowMeter) and
the CICFlowMeter orig-vs-fixed delta.

Captures labeled per tool:

- **nfstream**: 5/5 days (Friday, Monday, Thursday, Tuesday, Wednesday)
- **zeek**: 5/5 days (Friday, Monday, Thursday, Tuesday, Wednesday)
- **tranalyzer**: 5/5 days (Friday, Monday, Thursday, Tuesday, Wednesday)
- **cicflowmeter-orig**: 5/5 days (Friday, Monday, Thursday, Tuesday, Wednesday)
- **cicflowmeter-fixed**: 5/5 days (Friday, Monday, Thursday, Tuesday, Wednesday)
- **argus**: 5/5 days (Friday, Monday, Thursday, Tuesday, Wednesday)
- **go-flows**: 5/5 days (Friday, Monday, Thursday, Tuesday, Wednesday)
- **yaf**: 5/5 days (Friday, Monday, Thursday, Tuesday, Wednesday)
- **joy**: 5/5 days (Friday, Monday, Thursday, Tuesday, Wednesday)

| class | nfstream | zeek | tranalyzer | cicflowmeter-orig | cicflowmeter-fixed | argus | go-flows | yaf | joy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BENIGN | 1,579,826 | 1,657,370 | 1,569,277 | 1,946,290 | 1,656,781 | 1,113,501 | 1,799,989 | 1,732,809 | 2,409,313 |
| PortScan | 159,857 | 160,929 | 160,101 | 160,024 | 160,100 | 159,678 | 160,929 | 160,891 | 160,101 |
| DoS Hulk | 14,437 | 163,452 | 159,322 | 381,811 | 159,138 | 6,004 | 294,399 | 292,978 | 163,756 |
| DDoS | 63,540 | 95,683 | 95,683 | 190,259 | 95,683 | 45,206 | 95,732 | 95,241 | 108,625 |
| DoS GoldenEye | 7,656 | 7,739 | 7,496 | 10,490 | 7,780 | 0 | 7,656 | 7,574 | 11,094 |
| DoS slowloris | 4,515 | 3,902 | 3,895 | 5,725 | 5,731 | 3,895 | 4,515 | 3,897 | 14,334 |
| DoS Slowhttptest | 4,496 | 16,062 | 4,217 | 5,104 | 5,112 | 4,217 | 4,496 | 4,494 | 13,372 |
| FTP-Patator | 4,003 | 3,992 | 3,992 | 10,456 | 4,003 | 3,992 | 8,049 | 8,036 | 4,003 |
| SSH-Patator | 2,980 | 2,979 | 2,980 | 5,954 | 2,988 | 2,979 | 3,013 | 3,013 | 2,990 |
| Bot | 2,199 | 4,964 | 4,803 | 4,802 | 4,803 | 2,192 | 4,803 | 4,803 | 2,199 |
| Web Attack - Brute Force | 1,367 | 1,367 | 1,367 | 1,512 | 1,367 | 1,365 | 1,368 | 1,368 | 1,438 |
| Web Attack - XSS | 673 | 673 | 673 | 693 | 673 | 620 | 673 | 673 | 707 |
| Web Attack - Sql Injection | 18 | 18 | 18 | 30 | 18 | 17 | 19 | 19 | 18 |
| Infiltration | 36 | 49 | 43 | 81 | 78 | 32 | 50 | 49 | 138 |
| Heartbleed | 1 | 1 | 1 | 11 | 11 | 1 | 1 | 1 | 41 |

