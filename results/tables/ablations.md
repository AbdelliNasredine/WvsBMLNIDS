# Phase-4 ablations (cicids2017)

## Timeout ablation — total flow count vs idle timeout
See figures/timeout_sensitivity.png (Wednesday, focus class DoS Hulk). Fewer flows at longer timeout = more merging. Whether
tools converge at equal timeout tells us if the timeout *policy* (vs
tool identity) drove the divergence.

| tool | day | 15 | 60 | 120 | 600 |
| --- | --- | --- | --- | --- | --- |
| go-flows | Friday | 607488.0 | 577426.0 | 570138.0 | 545508.0 |
| go-flows | Wednesday | 708605.0 | 662149.0 | 649827.0 | 621732.0 |
| nfstream | Friday | 568551.0 | 538093.0 | 501096.0 | 458256.0 |
| nfstream | Wednesday | 540740.0 | 493777.0 | 337293.0 | 308709.0 |

## Directionality ablation — unidirectional vs bidirectional

| tool | bi_flows | uni_equiv_flows | uni/bi | %asymmetric_no_bwd |
| --- | --- | --- | --- | --- |
| argus | 1343699 | 2649670 | 1.972 | 0.028 |
| nfstream | 1845604 | 3637940 | 1.971 | 0.029 |
| zeek | 2119180 | 4150798 | 1.959 | 0.041 |
| yaf | 2315846 | 4343060 | 1.875 | 0.125 |
| tranalyzer | 2013868 | 3971933 | 1.972 | 0.028 |

## ML ablations (macro-F1 Δ vs R-common baseline, by setting)
dst_port is a **shortcut**: it helps in-distribution (stratified) but
hurts cross-time generalization (temporal). Label-noise (dropping
window-edge flows) has a negligible effect (robust labeling).

| ablation | task | split | n | mean_delta | median_delta |
| --- | --- | --- | --- | --- | --- |
| dst_port | binary | temporal | 54 | -0.0356 | 0.0046 |
| dst_port | multiclass | stratified | 54 | 0.0694 | 0.0573 |
| label_noise(exact) | binary | temporal | 54 | 0.0019 | 0.0 |
| label_noise(exact) | multiclass | stratified | 54 | 0.0189 | 0.0084 |

