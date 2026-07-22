# RQ4 — CICFlowMeter orig vs fixed: ML impact of the 'bug'

Same everything except the extractor code (the DistriNet fix removes
the TCP-appendix flows and corrects counting). Macro-F1 delta:

| regime | model | task | orig_macroF1 | fixed_macroF1 | delta(fixed-orig) |
| --- | --- | --- | --- | --- | --- |
| common | logreg | binary | 0.774 | 0.8075 | 0.0334 |
| common | mlp | binary | 0.7291 | 0.7095 | -0.0196 |
| common | rf | binary | 0.6801 | 0.5307 | -0.1494 |
| common | xgb | binary | 0.6665 | 0.9704 | 0.3039 |
| native | logreg | binary | 0.6732 | 0.7149 | 0.0417 |
| native | mlp | binary | 0.6413 | 0.7119 | 0.0706 |
| native | rf | binary | 0.4231 | 0.592 | 0.1689 |
| native | xgb | binary | 0.5819 | 0.6615 | 0.0796 |
| common | logreg | multiclass | 0.2186 | 0.3986 | 0.18 |
| common | mlp | multiclass | 0.5179 | 0.5933 | 0.0755 |
| common | rf | multiclass | 0.5887 | 0.6808 | 0.0921 |
| common | xgb | multiclass | 0.6017 | 0.7254 | 0.1237 |
| native | logreg | multiclass | 0.5488 | 0.6527 | 0.1038 |
| native | mlp | multiclass | 0.7904 | 0.8709 | 0.0804 |
| native | rf | multiclass | 0.8505 | 0.8614 | 0.0109 |
| native | xgb | multiclass | 0.8864 | 0.9193 | 0.0329 |


## Per-class recall delta (R-common RF multiclass)

| class | orig_recall | fixed_recall | delta |
| --- | --- | --- | --- |
| BENIGN | 0.963 | 0.987 | 0.024 |
| Bot | 0.951 | 0.969 | 0.018 |
| DDoS | 0.998 | 1.0 | 0.002 |
| DoS GoldenEye | 0.977 | 0.991 | 0.014 |
| DoS Hulk | 0.955 | 0.999 | 0.044 |
| DoS Slowhttptest | 0.922 | 0.93 | 0.008 |
| DoS slowloris | 0.987 | 0.983 | -0.004 |
| FTP-Patator | 0.76 | 0.994 | 0.234 |
| Heartbleed | 0.667 | 1.0 | 0.333 |
| Infiltration | 0.083 | 0.217 | 0.134 |
| PortScan | 0.997 | 0.999 | 0.002 |
| SSH-Patator | 0.509 | 0.978 | 0.469 |
| Web Attack - Brute Force | 0.132 | 0.156 | 0.024 |
| Web Attack - Sql Injection | 0.0 | 0.0 | 0.0 |
| Web Attack - XSS | 0.029 | 0.069 | 0.04 |

