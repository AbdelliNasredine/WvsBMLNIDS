# Flow-accounting divergence (RQ3)

From 704 ordered tool-pair × day matches over days: friday-pub, friday-pvt, monday-pub, monday-pvt, thursday-pub, thursday-pvt, tuesday-pub, tuesday-pvt, wednesday-pub, wednesday-pvt.
Match = order-independent 5-tuple + temporal overlap; each of A's flows
is 1:1, split (A coarser), merge (A finer), or unmatched vs B.

## Pairwise agreement (% of A's flows matching 1:1 to B)
row = A, col = B. See figures/agreement_heatmap.png.

| A \ B | nfstream | zeek | tranalyzer | cicflowmeter-orig | cicflowmeter-fixed | argus | go-flows | yaf | joy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| argus | 0.843 | 0.949 | 0.965 | 0.179 | 0.935 |  | 0.735 | 0.735 | 0.890 |
| cicflowmeter-fixed | 0.712 | 0.780 | 0.775 | 0.287 |  | 0.727 | 0.640 | 0.636 | 0.736 |
| cicflowmeter-orig | 0.093 | 0.083 | 0.091 |  | 0.216 | 0.104 | 0.093 | 0.092 | 0.086 |
| go-flows | 0.789 | 0.683 | 0.683 | 0.130 | 0.664 | 0.596 |  | 0.785 | 0.426 |
| joy | 0.286 | 0.485 | 0.261 | 0.073 | 0.478 | 0.437 | 0.258 | 0.255 |  |
| nfstream |  | 0.828 | 0.838 | 0.148 | 0.844 | 0.777 | 0.897 | 0.852 | 0.536 |
| tranalyzer | 0.844 | 0.961 |  | 0.147 | 0.925 | 0.896 | 0.782 | 0.781 | 0.492 |
| yaf | 0.759 | 0.688 | 0.691 | 0.131 | 0.669 | 0.604 | 0.795 |  | 0.425 |
| zeek | 0.798 |  | 0.919 | 0.127 | 0.889 | 0.843 | 0.748 | 0.745 | 0.877 |

## Divergence by traffic class (aggregated over all tool pairs)
H3: attack traffic should show far lower 1:1 (more split/merge) than benign.
See figures/per_class_split.png.

| class | n | 1to1_frac | split_frac | merge_frac | unmatched_frac |
| --- | --- | --- | --- | --- | --- |
| BENIGN | 3430313 | 0.496 | 0.049 | 0.200 | 0.256 |
| Reconnaissance | 512184 | 0.691 | 0.039 | 0.069 | 0.201 |
| Establish Foothold | 366912 | 0.718 | 0.037 | 0.064 | 0.181 |
| Lateral Movement | 113928 | 0.419 | 0.011 | 0.021 | 0.549 |
| Data Exfiltration | 80 | 0.400 | 0.000 | 0.375 | 0.225 |

