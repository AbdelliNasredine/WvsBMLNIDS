# Feature-value divergence on 1:1 matched flows (RQ2/RQ3)

For flows that BOTH tools segment identically (1:1), how much do the
*values* of nominally-identical features differ? relative error =
(B-A)/(|A|+1); KS = 2-sample KS statistic between the tools' value
distributions on the matched flows. Byte counts differ by construction
(IP vs payload vs L7 semantics); duration/packets should be close.

| pair | feature | n_1to1 | median_rel_err | mean_abs_rel_err | frac_within_5pct | ks_stat |
| --- | --- | --- | --- | --- | --- | --- |
| cicflowmeter-orig vs cicflowmeter-fixed | duration | 12069 | 0.0 | 0.0449 | 0.8441 | 0.1507 |
| cicflowmeter-orig vs cicflowmeter-fixed | tot_pkts | 12069 | 0.0 | 8.232 | 0.7162 | 0.248 |
| cicflowmeter-orig vs cicflowmeter-fixed | tot_bytes | 12069 | 0.0 | 8473.7056 | 0.8401 | 0.1594 |
| nfstream vs zeek | duration | 42250 | -0.0 | 0.0019 | 0.9979 | 0.1684 |
| nfstream vs zeek | tot_pkts | 42250 | 0.0 | 0.0004 | 0.9987 | 0.0013 |
| nfstream vs zeek | tot_bytes | 42250 | 0.0 | 0.0005 | 0.9986 | 0.0013 |
| zeek vs tranalyzer | duration | 48950 | -0.0 | 0.0112 | 0.9904 | 0.4289 |
| zeek vs tranalyzer | tot_pkts | 48950 | 0.0 | 0.0 | 1.0 | 0.0 |
| zeek vs tranalyzer | tot_bytes | 48950 | -0.2902 | 0.3731 | 0.0193 | 0.3234 |
| nfstream vs yaf | duration | 43350 | 0.0 | 0.0045 | 0.9998 | 0.1086 |
| nfstream vs yaf | tot_pkts | 43350 | 0.0 | 0.0006 | 0.996 | 0.0032 |
| nfstream vs yaf | tot_bytes | 43350 | 0.0 | 0.0004 | 0.9987 | 0.001 |

