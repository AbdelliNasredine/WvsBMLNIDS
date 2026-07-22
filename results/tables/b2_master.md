# Phase-B2 unified black-box vs white-box (cicids2017)

360 runs. Every extractor -- 5 NFM embeddings + NFStream hand-engineered
features -- is evaluated on the IDENTICAL 142k flows, same heads/splits/seeds.

## multiclass / stratified -- macro-F1 (mean over seeds)
| tool | logreg | mlp | rf | xgb |
| --- | --- | --- | --- | --- |
| raw-cnn | 0.6800 | 0.7391 | 0.7357 | 0.7535 |
| yatc | 0.8335 | 0.8423 | 0.7701 | 0.8009 |
| etbert | 0.8582 | 0.8490 | 0.6788 | 0.7911 |
| netfound | 0.8130 | 0.7782 | 0.7742 | 0.7961 |
| nfstream-common | 0.5822 | 0.6951 | 0.8126 | 0.8129 |
| nfstream-native | 0.7207 | 0.7881 | 0.8369 | 0.8372 |

*RQ-B1 (best head): NFM spread = 0.105 (best etbert 0.858 via logreg, worst raw-cnn 0.753).*
*RQ-B2 (best head): best NFM 0.858 (etbert/logreg) beat NFStream-native 0.837/common 0.813 on identical flows.*

## binary / temporal -- macro-F1 (mean over seeds)
| tool | logreg | mlp | rf | xgb |
| --- | --- | --- | --- | --- |
| raw-cnn | 0.8631 | 0.6481 | 0.5046 | 0.5218 |
| yatc | 0.6727 | 0.4882 | 0.5761 | 0.5829 |
| etbert | 0.3653 | 0.3409 | 0.3061 | 0.3376 |
| netfound | 0.4314 | 0.4003 | 0.3577 | 0.4367 |
| nfstream-common | 0.8488 | 0.9055 | 0.5486 | 0.6089 |
| nfstream-native | 0.7659 | 0.6026 | 0.5073 | 0.4746 |

*RQ-B1 (best head): NFM spread = 0.498 (best raw-cnn 0.863 via logreg, worst etbert 0.365).*
*RQ-B2 (best head): best NFM 0.863 (raw-cnn/logreg) lose to NFStream-native 0.766/common 0.906 on identical flows.*

## binary / stratified -- macro-F1 (mean over seeds)
| tool | logreg | mlp | rf | xgb |
| --- | --- | --- | --- | --- |
| raw-cnn | 0.9465 | 0.9938 | 0.9894 | 0.9937 |
| yatc | 0.9964 | 0.9988 | 0.9932 | 0.9978 |
| etbert | 0.9851 | 0.9939 | 0.9620 | 0.9841 |
| netfound | 0.9986 | 0.9984 | 0.9984 | 0.9986 |
| nfstream-common | 0.8607 | 0.9856 | 0.9946 | 0.9959 |
| nfstream-native | 0.9700 | 0.9978 | 0.9988 | 0.9989 |

*RQ-B1 (best head): NFM spread = 0.005 (best yatc 0.999 via mlp, worst raw-cnn 0.994).*
*RQ-B2 (best head): best NFM 0.999 (yatc/mlp) lose to NFStream-native 0.999/common 0.996 on identical flows.*

