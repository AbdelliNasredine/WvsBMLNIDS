# Feature-value divergence on 1:1 matched flows (RQ2/RQ3)

For flows that BOTH tools segment identically (1:1), how much do the
*values* of nominally-identical features differ? relative error =
(B-A)/(|A|+1); KS = 2-sample KS statistic between the tools' value
distributions on the matched flows. Byte counts differ by construction
(IP vs payload vs L7 semantics); duration/packets should be close.

| pair | feature | n_1to1 | median_rel_err | mean_abs_rel_err | frac_within_5pct | ks_stat |
| --- | --- | --- | --- | --- | --- | --- |
| cicflowmeter-orig vs cicflowmeter-fixed | duration | 528924 | 0.0 | 0.0788 | 0.8825 | 0.0393 |
| cicflowmeter-orig vs cicflowmeter-fixed | tot_pkts | 528924 | 0.0312 | 0.4152 | 0.5567 | 0.18 |
| cicflowmeter-orig vs cicflowmeter-fixed | tot_bytes | 528924 | 0.0 | 1422.7499 | 0.8689 | 0.1225 |
| nfstream vs zeek | duration | 1253964 | -0.0 | 0.0068 | 0.9798 | 0.0798 |
| nfstream vs zeek | tot_pkts | 1253964 | 0.0 | 0.0013 | 0.9964 | 0.0022 |
| nfstream vs zeek | tot_bytes | 1253964 | 0.0 | 0.0024 | 0.9949 | 0.0014 |
| zeek vs tranalyzer | duration | 1926514 | -0.0001 | 0.0203 | 0.8837 | 0.4774 |
| zeek vs tranalyzer | tot_pkts | 1926514 | 0.0 | 0.0008 | 0.9961 | 0.001 |
| zeek vs tranalyzer | tot_bytes | 1926514 | -0.2605 | 0.3386 | 0.0571 | 0.1773 |
| nfstream vs yaf | duration | 1402995 | 0.0 | 0.1579 | 0.9986 | 0.0492 |
| nfstream vs yaf | tot_pkts | 1402995 | 0.0 | 0.0016 | 0.9924 | 0.0008 |
| nfstream vs yaf | tot_bytes | 1402995 | 0.0 | 0.0014 | 0.997 | 0.0004 |

