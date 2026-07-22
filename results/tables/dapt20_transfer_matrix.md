# RQ2 cross-tool transfer matrix (binary macro-F1)

Train a RandomForest on tool A's R-common features, test on tool B's.
Mean diagonal (within-tool): **0.875**; mean off-diagonal
(transfer): **0.773**; mean drop **0.102**.
A large drop means the same features carry tool-specific values.

| train \ test | nfs | zeek | tran | cfm-o | cfm-f | argus | goflw | yaf | joy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| nfs | 0.857 | 0.864 | 0.817 | 0.681 | 0.869 | 0.876 | 0.429 | 0.848 | 0.833 |
| zeek | 0.877 | 0.890 | 0.818 | 0.669 | 0.872 | 0.879 | 0.429 | 0.835 | 0.834 |
| tran | 0.846 | 0.839 | 0.899 | 0.767 | 0.973 | 0.800 | 0.429 | 0.811 | 0.911 |
| cfm-o | 0.843 | 0.845 | 0.779 | 0.844 | 0.789 | 0.804 | 0.429 | 0.810 | 0.804 |
| cfm-f | 0.822 | 0.816 | 0.929 | 0.755 | 0.949 | 0.804 | 0.429 | 0.792 | 0.922 |
| argus | 0.906 | 0.902 | 0.810 | 0.675 | 0.853 | 0.891 | 0.429 | 0.858 | 0.809 |
| goflw | 0.776 | 0.744 | 0.771 | 0.645 | 0.823 | 0.721 | 0.843 | 0.764 | 0.775 |
| yaf | 0.879 | 0.860 | 0.818 | 0.669 | 0.859 | 0.893 | 0.510 | 0.846 | 0.811 |
| joy | 0.757 | 0.746 | 0.858 | 0.709 | 0.960 | 0.772 | 0.429 | 0.702 | 0.857 |
