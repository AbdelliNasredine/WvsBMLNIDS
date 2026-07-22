# Phase-B2 unified black-box vs white-box (dapt20)

360 runs. Every extractor -- 5 NFM embeddings + NFStream hand-engineered
features -- is evaluated on the IDENTICAL 142k flows, same heads/splits/seeds.

## multiclass / stratified -- macro-F1 (mean over seeds)
| tool | logreg | mlp | rf | xgb |
| --- | --- | --- | --- | --- |
| raw-cnn | 0.6959 | 0.6302 | 0.5816 | 0.6040 |
| yatc | 0.6895 | 0.6924 | 0.5885 | 0.6067 |
| etbert | 0.7334 | 0.6803 | 0.5060 | 0.5858 |
| netfound | 0.7902 | 0.6454 | 0.6490 | 0.6516 |
| nfstream-common | 0.4574 | 0.5530 | 0.8007 | 0.5973 |
| nfstream-native | 0.6787 | 0.5630 | 0.7223 | 0.6895 |

*RQ-B1 (best head): NFM spread = 0.098 (best netfound 0.790 via logreg, worst yatc 0.692).*
*RQ-B2 (best head): best NFM 0.790 (netfound/logreg) lose to NFStream-native 0.722/common 0.801 on identical flows.*

## binary / temporal -- macro-F1 (mean over seeds)
| tool | logreg | mlp | rf | xgb |
| --- | --- | --- | --- | --- |
| raw-cnn | 0.6172 | 0.5660 | 0.5475 | 0.5653 |
| yatc | 0.5070 | 0.5014 | 0.4921 | 0.4994 |
| etbert | 0.5490 | 0.5261 | 0.5226 | 0.5275 |
| netfound | 0.5032 | 0.4991 | 0.4981 | 0.5028 |
| nfstream-common | 0.6726 | 0.6232 | 0.4894 | 0.4933 |
| nfstream-native | 0.6244 | 0.4972 | 0.4974 | 0.4997 |

*RQ-B1 (best head): NFM spread = 0.114 (best raw-cnn 0.617 via logreg, worst netfound 0.503).*
*RQ-B2 (best head): best NFM 0.617 (raw-cnn/logreg) lose to NFStream-native 0.624/common 0.673 on identical flows.*

## binary / stratified -- macro-F1 (mean over seeds)
| tool | logreg | mlp | rf | xgb |
| --- | --- | --- | --- | --- |
| raw-cnn | 0.8793 | 0.9096 | 0.8845 | 0.8901 |
| yatc | 0.9103 | 0.9295 | 0.8850 | 0.8954 |
| etbert | 0.9118 | 0.9331 | 0.8384 | 0.8776 |
| netfound | 0.9149 | 0.9141 | 0.9071 | 0.9110 |
| nfstream-common | 0.7997 | 0.8879 | 0.8558 | 0.9067 |
| nfstream-native | 0.8801 | 0.9084 | 0.8614 | 0.9123 |

*RQ-B1 (best head): NFM spread = 0.023 (best etbert 0.933 via mlp, worst raw-cnn 0.910).*
*RQ-B2 (best head): best NFM 0.933 (etbert/mlp) beat NFStream-native 0.912/common 0.907 on identical flows.*

