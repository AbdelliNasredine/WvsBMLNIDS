# Phase-B5 label efficiency + zero-shot (cicids2017)

## k-shot label efficiency (multiclass macro-F1, LogReg, mean/5 seeds)
| extractor | 1 | 5 | 10 | 50 | 100 |
| --- | --- | --- | --- | --- | --- |
| raw-cnn | 0.326 | 0.474 | 0.510 | 0.572 | 0.596 |
| yatc | 0.312 | 0.507 | 0.563 | 0.667 | 0.696 |
| etbert | 0.278 | 0.447 | 0.507 | 0.632 | 0.681 |
| netfound | 0.414 | 0.561 | 0.600 | 0.673 | 0.691 |
| nfstream-common | 0.160 | 0.197 | 0.300 | 0.465 | 0.492 |
| nfstream-native | 0.465 | 0.578 | 0.605 | 0.650 | 0.657 |

*k=5: best nfstream-native 0.578; NFStream-native 0.578 (rank 1/6).*
*k=100: best yatc 0.696; NFStream-native 0.657 (rank 4/6).*

## Zero-shot anomaly detection (benign-only train; best detector per extractor)
| extractor | detector | auc_pr | auc_roc |
| --- | --- | --- | --- |
| raw-cnn | knn | 0.701 | 0.671 |
| yatc | ocsvm | 0.679 | 0.641 |
| etbert | knn | 0.814 | 0.761 |
| netfound | knn | 0.931 | 0.918 |
| nfstream-common | mahalanobis | 0.852 | 0.841 |
| nfstream-native | mahalanobis | 0.931 | 0.912 |

*Best zero-shot: netfound AUC-PR 0.931; NFStream-native 0.931.*
