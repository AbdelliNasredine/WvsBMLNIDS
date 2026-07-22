# RQ4 — CICFlowMeter orig vs fixed: ML impact of the 'bug'

Same everything except the extractor code (the DistriNet fix removes
the TCP-appendix flows and corrects counting). Macro-F1 delta:

| regime | model | task | orig_macroF1 | fixed_macroF1 | delta(fixed-orig) |
| --- | --- | --- | --- | --- | --- |
| common | logreg | binary | 0.653 | 0.4504 | -0.2027 |
| common | mlp | binary | 0.6156 | 0.4974 | -0.1182 |
| common | rf | binary | 0.5444 | 0.5465 | 0.0022 |
| common | xgb | binary | 0.6353 | 0.4795 | -0.1558 |
| native | logreg | binary | 0.6287 | 0.4496 | -0.1791 |
| native | mlp | binary | 0.556 | 0.6776 | 0.1216 |
| native | rf | binary | 0.5278 | 0.7926 | 0.2648 |
| native | xgb | binary | 0.5094 | 0.7409 | 0.2315 |
| common | logreg | multiclass | 0.3822 | 0.5594 | 0.1772 |
| common | mlp | multiclass | 0.4569 | 0.694 | 0.2371 |
| common | rf | multiclass | 0.5537 | 0.7392 | 0.1855 |
| common | xgb | multiclass | 0.5707 | 0.7193 | 0.1486 |
| native | logreg | multiclass | 0.6695 | 0.7323 | 0.0628 |
| native | mlp | multiclass | 0.7562 | 0.7978 | 0.0415 |
| native | rf | multiclass | 0.7801 | 0.8504 | 0.0703 |
| native | xgb | multiclass | 0.7918 | 0.9276 | 0.1358 |


## Per-class recall delta (R-common RF multiclass)

| class | orig_recall | fixed_recall | delta |
| --- | --- | --- | --- |
| BENIGN | 0.829 | 0.983 | 0.154 |
| Data Exfiltration | 0.0 | nan | nan |
| Establish Foothold | 0.856 | 0.936 | 0.08 |
| Lateral Movement | 0.813 | 0.12 | -0.693 |
| Reconnaissance | 0.725 | 0.874 | 0.149 |

