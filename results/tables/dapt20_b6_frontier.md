# RQ-B6 cost-performance frontier (CIC-IDS2017, shared 142k flows)

End-to-end throughput = shared PcapPlusPlus assembly (590 flows/s) + per-model
embedding (NFMs); NFStream = one native pass. Best macro-F1 from the B2 grid.

| extractor | family | hardware | e2e_fps | embed_fps | dim | gpu_gb | kb_per_flow | best_macro_f1 | pareto |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| nfstream-common | whitebox | CPU | 2058.0 | 2058.0 | 9 | 0.0 | 0.1 | 0.801 | True |
| nfstream-native | whitebox | CPU | 2058.0 | 2058.0 | 58 | 0.0 | 0.1 | 0.722 | False |
| raw-cnn | nfm | CPU+GPU | 457.6 | 2040.1 | 128 | 0.3 | 0.5 | 0.696 | False |
| yatc | nfm | CPU+GPU | 227.2 | 369.6 | 192 | 6.5 | 0.8 | 0.692 | False |
| etbert | nfm | CPU+GPU | 42.0 | 45.2 | 768 | 2.7 | 3.1 | 0.733 | False |
| netfound | nfm | CPU+GPU | 23.0 | 23.9 | 1024 | 10.2 | 4.1 | 0.79 | False |

**Pareto-optimal:** nfstream-common.
