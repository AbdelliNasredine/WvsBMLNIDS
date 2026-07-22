# Phase-3 ML results (RQ1) — master table

1080 runs; macro-F1 mean±std over seeds. Extractor is the only
independent variable within each (regime, model, task, split).

## binary — R-common (stratified) — macro-F1
tool-induced spread (max−min across tools/models): **0.2258**

| tool | logreg | mlp | rf | xgb |
| --- | --- | --- | --- | --- |
| nfstream | 0.8231 | 0.9901 | 0.9936 | 0.9952 |
| zeek | 0.8707 | 0.9752 | 0.9829 | 0.9872 |
| tranalyzer | 0.8769 | 0.9876 | 0.9899 | 0.9894 |
| cicflowmeter-orig | 0.8006 | 0.9363 | 0.9656 | 0.9671 |
| cicflowmeter-fixed | 0.8639 | 0.9805 | 0.9855 | 0.9866 |
| argus | 0.8012 | 0.9895 | 0.9942 | 0.9959 |
| go-flows | 0.8198 | 0.8977 | 0.9147 | 0.9342 |
| yaf | 0.8201 | 0.9184 | 0.9153 | 0.9359 |
| joy | 0.7701 | 0.9810 | 0.9837 | 0.9847 |

## binary — R-native (stratified) — macro-F1
tool-induced spread (max−min across tools/models): **0.1943**

| tool | logreg | mlp | rf | xgb |
| --- | --- | --- | --- | --- |
| nfstream | 0.9699 | 0.9952 | 0.9979 | 0.9980 |
| zeek | 0.9599 | 0.9983 | 0.9997 | 0.9997 |
| tranalyzer | 0.9989 | 0.9999 | 1.0000 | 1.0000 |
| cicflowmeter-orig | 0.9383 | 0.9913 | 0.9946 | 0.9980 |
| cicflowmeter-fixed | 0.9778 | 0.9918 | 0.9936 | 0.9984 |
| argus | 0.8236 | 0.9937 | 0.9995 | 0.9994 |
| go-flows | 0.8648 | 0.9971 | 0.9997 | 0.9997 |
| yaf | 0.8056 | 0.9826 | 0.9906 | 0.9967 |
| joy | 0.8544 | 0.9816 | 0.9930 | 0.9927 |

## multiclass — R-common (stratified) — macro-F1
tool-induced spread (max−min across tools/models): **0.5120**

| tool | logreg | mlp | rf | xgb |
| --- | --- | --- | --- | --- |
| nfstream | 0.4414 | 0.6298 | 0.7287 | 0.6901 |
| zeek | 0.4053 | 0.5688 | 0.6572 | 0.6580 |
| tranalyzer | 0.4545 | 0.6009 | 0.6303 | 0.6513 |
| cicflowmeter-orig | 0.2200 | 0.4962 | 0.5911 | 0.6107 |
| cicflowmeter-fixed | 0.3995 | 0.5974 | 0.6702 | 0.6969 |
| argus | 0.4562 | 0.5948 | 0.7319 | 0.6880 |
| go-flows | 0.3010 | 0.4956 | 0.5520 | 0.5714 |
| yaf | 0.3352 | 0.5453 | 0.5694 | 0.6091 |
| joy | 0.3088 | 0.6081 | 0.6749 | 0.7200 |

## multiclass — R-native (stratified) — macro-F1
tool-induced spread (max−min across tools/models): **0.5971**

| tool | logreg | mlp | rf | xgb |
| --- | --- | --- | --- | --- |
| nfstream | 0.5599 | 0.6649 | 0.7842 | 0.7997 |
| zeek | 0.5508 | 0.7249 | 0.8501 | 0.8692 |
| tranalyzer | 0.8273 | 0.8230 | 0.9088 | 0.8969 |
| cicflowmeter-orig | 0.5609 | 0.8017 | 0.8510 | 0.8981 |
| cicflowmeter-fixed | 0.6653 | 0.8576 | 0.8816 | 0.9276 |
| argus | 0.4289 | 0.6356 | 0.8628 | 0.8712 |
| go-flows | 0.3305 | 0.7087 | 0.8487 | 0.8869 |
| yaf | 0.3309 | 0.7312 | 0.8331 | 0.8400 |
| joy | 0.3689 | 0.7099 | 0.7718 | 0.8025 |

