# RQ2 cross-tool transfer matrix (binary macro-F1)

Train a RandomForest on tool A's R-common features, test on tool B's.
Mean diagonal (within-tool): **0.969**; mean off-diagonal
(transfer): **0.699**; mean drop **0.271**.
A large drop means the same features carry tool-specific values.

| train \ test | nfs | zeek | tran | cfm-o | cfm-f | argus | goflw | yaf | joy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| nfs | 0.993 | 0.977 | 0.731 | 0.611 | 0.728 | 0.958 | 0.553 | 0.877 | 0.733 |
| zeek | 0.937 | 0.982 | 0.732 | 0.463 | 0.500 | 0.794 | 0.434 | 0.908 | 0.727 |
| tran | 0.609 | 0.815 | 0.990 | 0.797 | 0.980 | 0.564 | 0.422 | 0.755 | 0.868 |
| cfm-o | 0.551 | 0.598 | 0.989 | 0.966 | 0.985 | 0.517 | 0.430 | 0.562 | 0.961 |
| cfm-f | 0.596 | 0.689 | 0.991 | 0.821 | 0.986 | 0.529 | 0.423 | 0.643 | 0.959 |
| argus | 0.930 | 0.922 | 0.695 | 0.697 | 0.697 | 0.994 | 0.597 | 0.828 | 0.716 |
| goflw | 0.511 | 0.554 | 0.455 | 0.418 | 0.457 | 0.467 | 0.915 | 0.562 | 0.510 |
| yaf | 0.973 | 0.982 | 0.802 | 0.604 | 0.801 | 0.582 | 0.726 | 0.915 | 0.783 |
| joy | 0.604 | 0.606 | 0.963 | 0.766 | 0.836 | 0.555 | 0.429 | 0.562 | 0.984 |
