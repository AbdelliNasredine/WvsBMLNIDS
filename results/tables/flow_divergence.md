# Flow-accounting divergence (RQ3)

From 360 ordered tool-pair × day matches over days: Friday, Monday, Thursday, Tuesday, Wednesday.
Match = order-independent 5-tuple + temporal overlap; each of A's flows
is 1:1, split (A coarser), merge (A finer), or unmatched vs B.

## Pairwise agreement (% of A's flows matching 1:1 to B)
row = A, col = B. See figures/agreement_heatmap.png.

| A \ B | nfstream | zeek | tranalyzer | cicflowmeter-orig | cicflowmeter-fixed | argus | go-flows | yaf | joy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| argus | 0.629 | 0.866 | 0.872 | 0.275 | 0.836 |  | 0.524 | 0.526 | 0.724 |
| cicflowmeter-fixed | 0.592 | 0.923 | 0.885 | 0.251 |  | 0.534 | 0.598 | 0.550 | 0.814 |
| cicflowmeter-orig | 0.136 | 0.162 | 0.161 |  | 0.194 | 0.136 | 0.152 | 0.157 | 0.125 |
| go-flows | 0.683 | 0.546 | 0.538 | 0.174 | 0.527 | 0.295 |  | 0.696 | 0.219 |
| joy | 0.164 | 0.625 | 0.301 | 0.118 | 0.592 | 0.336 | 0.181 | 0.183 |  |
| nfstream |  | 0.679 | 0.677 | 0.200 | 0.675 | 0.458 | 0.883 | 0.760 | 0.256 |
| tranalyzer | 0.620 | 0.957 |  | 0.218 | 0.924 | 0.582 | 0.638 | 0.615 | 0.433 |
| yaf | 0.606 | 0.523 | 0.535 | 0.184 | 0.500 | 0.305 | 0.717 |  | 0.228 |
| zeek | 0.592 |  | 0.909 | 0.208 | 0.916 | 0.549 | 0.614 | 0.572 | 0.853 |

## Divergence by traffic class (aggregated over all tool pairs)
H3: attack traffic should show far lower 1:1 (more split/merge) than benign.
See figures/per_class_split.png.

| class | n | 1to1_frac | split_frac | merge_frac | unmatched_frac |
| --- | --- | --- | --- | --- | --- |
| BENIGN | 123721248 | 0.500 | 0.055 | 0.168 | 0.276 |
| PortScan | 11540880 | 0.360 | 0.001 | 0.001 | 0.638 |
| DoS Hulk | 13082376 | 0.288 | 0.108 | 0.431 | 0.173 |
| DDoS | 7085216 | 0.578 | 0.105 | 0.263 | 0.054 |
| DoS GoldenEye | 539880 | 0.662 | 0.062 | 0.252 | 0.023 |
| DoS slowloris | 403272 | 0.474 | 0.125 | 0.360 | 0.041 |
| DoS Slowhttptest | 492560 | 0.304 | 0.177 | 0.451 | 0.068 |
| FTP-Patator | 404208 | 0.306 | 0.222 | 0.445 | 0.026 |
| SSH-Patator | 239008 | 0.696 | 0.100 | 0.200 | 0.003 |
| Bot | 284544 | 0.426 | 0.077 | 0.209 | 0.288 |
| Web Attack - Brute Force | 100152 | 0.939 | 0.022 | 0.038 | 0.000 |
| Web Attack - XSS | 48464 | 0.971 | 0.006 | 0.023 | 0.000 |
| Web Attack - Sql Injection | 1400 | 0.749 | 0.080 | 0.160 | 0.011 |
| Infiltration | 4448 | 0.314 | 0.062 | 0.367 | 0.257 |
| Heartbleed | 552 | 0.087 | 0.092 | 0.821 | 0.000 |

