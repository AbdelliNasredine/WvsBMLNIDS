# Phase-3 ML results (RQ1) — master table

1080 runs; macro-F1 mean±std over seeds. Extractor is the only
independent variable within each (regime, model, task, split).

## binary — R-common (stratified) — macro-F1
tool-induced spread (max−min across tools/models): **0.2750**

| tool | logreg | mlp | rf | xgb |
| --- | --- | --- | --- | --- |
| nfstream | 0.8007 | 0.8836 | 0.8561 | 0.9080 |
| zeek | 0.7605 | 0.8879 | 0.8892 | 0.9160 |
| tranalyzer | 0.7964 | 0.8863 | 0.8975 | 0.9017 |
| cicflowmeter-orig | 0.7673 | 0.8528 | 0.8405 | 0.9198 |
| cicflowmeter-fixed | 0.7880 | 0.9350 | 0.9492 | 0.9529 |
| argus | 0.7088 | 0.8832 | 0.8917 | 0.9083 |
| go-flows | 0.7379 | 0.8508 | 0.8449 | 0.8875 |
| yaf | 0.7395 | 0.8526 | 0.8492 | 0.8919 |
| joy | 0.6779 | 0.9018 | 0.8553 | 0.9146 |

## binary — R-native (stratified) — macro-F1
tool-induced spread (max−min across tools/models): **0.2462**

| tool | logreg | mlp | rf | xgb |
| --- | --- | --- | --- | --- |
| nfstream | 0.8811 | 0.9120 | 0.8619 | 0.9137 |
| zeek | 0.8628 | 0.9322 | 0.9753 | 0.9793 |
| tranalyzer | 0.9564 | 0.9914 | 0.9979 | 0.9989 |
| cicflowmeter-orig | 0.8889 | 0.9678 | 0.9880 | 0.9963 |
| cicflowmeter-fixed | 0.9160 | 0.9807 | 0.9846 | 0.9959 |
| argus | 0.7527 | 0.8773 | 0.9743 | 0.9802 |
| go-flows | 0.8479 | 0.9396 | 0.9404 | 0.9446 |
| yaf | 0.8664 | 0.9476 | 0.9916 | 0.9941 |
| joy | 0.8366 | 0.9260 | 0.9221 | 0.9402 |

## multiclass — R-common (stratified) — macro-F1
tool-induced spread (max−min across tools/models): **0.4752**

| tool | logreg | mlp | rf | xgb |
| --- | --- | --- | --- | --- |
| nfstream | 0.4578 | 0.5523 | 0.8021 | 0.5919 |
| zeek | 0.6092 | 0.6812 | 0.8242 | 0.8135 |
| tranalyzer | 0.6531 | 0.6901 | 0.7708 | 0.7349 |
| cicflowmeter-orig | 0.3686 | 0.4526 | 0.5551 | 0.5960 |
| cicflowmeter-fixed | 0.5598 | 0.6998 | 0.7498 | 0.7152 |
| argus | 0.5556 | 0.6822 | 0.8377 | 0.7509 |
| go-flows | 0.3625 | 0.5125 | 0.7128 | 0.5503 |
| yaf | 0.4434 | 0.5195 | 0.7176 | 0.5735 |
| joy | 0.4501 | 0.5591 | 0.8283 | 0.5951 |

## multiclass — R-native (stratified) — macro-F1
tool-induced spread (max−min across tools/models): **0.4499**

| tool | logreg | mlp | rf | xgb |
| --- | --- | --- | --- | --- |
| nfstream | 0.6637 | 0.5940 | 0.6841 | 0.8103 |
| zeek | 0.7344 | 0.7948 | 0.9384 | 0.9478 |
| tranalyzer | 0.9468 | 0.9891 | 0.9971 | 0.9986 |
| cicflowmeter-orig | 0.6753 | 0.7544 | 0.7807 | 0.7914 |
| cicflowmeter-fixed | 0.7344 | 0.7825 | 0.8750 | 0.9354 |
| argus | 0.5487 | 0.7131 | 0.9413 | 0.9521 |
| go-flows | 0.7152 | 0.6656 | 0.6842 | 0.6677 |
| yaf | 0.6373 | 0.6798 | 0.7879 | 0.8318 |
| joy | 0.5636 | 0.6524 | 0.6773 | 0.7046 |

