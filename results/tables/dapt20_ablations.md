# Phase-4 ablations (dapt20)

## Timeout ablation — total flow count vs idle timeout
See figures/dapt20_timeout_sensitivity.png (thursday-pvt, focus class Lateral Movement). Fewer flows at longer timeout = more merging. Whether
tools converge at equal timeout tells us if the timeout *policy* (vs
tool identity) drove the divergence.

| tool | day | 15 | 60 | 120 | 600 |
| --- | --- | --- | --- | --- | --- |
| go-flows | thursday-pvt | 4748.0 | 2314.0 | 2294.0 | 2278.0 |
| go-flows | wednesday-pub | 14868.0 | 12213.0 | 12187.0 | 12091.0 |
| nfstream | thursday-pvt | 4676.0 | 2243.0 | 2223.0 | 2202.0 |
| nfstream | wednesday-pub | 12922.0 | 10235.0 | 10208.0 | 10107.0 |

## Directionality ablation — unidirectional vs bidirectional

| tool | bi_flows | uni_equiv_flows | uni/bi | %asymmetric_no_bwd |
| --- | --- | --- | --- | --- |
| argus | 47405 | 93437 | 1.971 | 0.029 |
| nfstream | 51410 | 99722 | 1.94 | 0.06 |
| zeek | 53339 | 101707 | 1.907 | 0.093 |
| yaf | 57729 | 107129 | 1.856 | 0.144 |
| tranalyzer | 51042 | 99790 | 1.955 | 0.045 |

## ML ablations (macro-F1 Δ vs R-common baseline, by setting)
dst_port is a **shortcut**: it helps in-distribution (stratified) but
hurts cross-time generalization (temporal). Label-noise (dropping
window-edge flows) has a negligible effect (robust labeling).

| ablation | task | split | n | mean_delta | median_delta |
| --- | --- | --- | --- | --- | --- |
| dst_port | binary | temporal | 54 | 0.0179 | 0.0079 |
| dst_port | multiclass | stratified | 54 | -0.026 | 0.0035 |
| label_noise(exact) | binary | temporal | 54 | -0.0049 | 0.0 |
| label_noise(exact) | multiclass | stratified | 54 | -0.0099 | 0.0001 |

