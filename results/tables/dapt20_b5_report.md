# Phase-B5 label efficiency + zero-shot (dapt20)

## k-shot label efficiency (multiclass macro-F1, LogReg, mean/5 seeds)
| extractor | 1 | 5 | 10 | 50 | 100 |
| --- | --- | --- | --- | --- | --- |
| raw-cnn | 0.305 | 0.443 | 0.451 | 0.559 | 0.579 |
| yatc | 0.329 | 0.482 | 0.504 | 0.618 | 0.650 |
| etbert | 0.290 | 0.393 | 0.447 | 0.536 | 0.586 |
| netfound | 0.315 | 0.488 | 0.532 | 0.622 | 0.662 |
| nfstream-common | 0.316 | 0.398 | 0.365 | 0.396 | 0.406 |
| nfstream-native | 0.339 | 0.496 | 0.548 | 0.563 | 0.561 |

*k=5: best nfstream-native 0.496; NFStream-native 0.496 (rank 1/6).*
*k=100: best netfound 0.662; NFStream-native 0.561 (rank 5/6).*

## Zero-shot anomaly detection (benign-only train; best detector per extractor)
| extractor | detector | auc_pr | auc_roc |
| --- | --- | --- | --- |
| raw-cnn | mahalanobis | 0.480 | 0.814 |
| yatc | knn | 0.655 | 0.838 |
| etbert | knn | 0.416 | 0.771 |
| netfound | knn | 0.594 | 0.859 |
| nfstream-common | knn | 0.465 | 0.802 |
| nfstream-native | knn | 0.442 | 0.808 |

*Best zero-shot: yatc AUC-PR 0.655; NFStream-native 0.442.*
