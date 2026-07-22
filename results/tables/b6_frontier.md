# RQ-B6 cost-performance frontier (CIC-IDS2017, shared 142k flows)

End-to-end throughput = shared PcapPlusPlus assembly (590 flows/s) + per-model
embedding (NFMs); NFStream = one native pass. Best macro-F1 from the B2 grid.

| extractor | family | hardware | e2e_fps | embed_fps | dim | gpu_gb | kb_per_flow | best_macro_f1 | pareto |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| nfstream-common | whitebox | CPU | 2058.0 | 2058.0 | 9 | 0.0 | 0.1 | 0.813 | True |
| nfstream-native | whitebox | CPU | 2058.0 | 2058.0 | 58 | 0.0 | 0.1 | 0.837 | True |
| raw-cnn | nfm | CPU+GPU | 528.9 | 5103.2 | 128 | 0.6 | 0.5 | 0.753 | False |
| yatc | nfm | CPU+GPU | 207.9 | 321.0 | 192 | 12.9 | 0.8 | 0.842 | True |
| etbert | nfm | CPU+GPU | 46.7 | 50.7 | 768 | 4.7 | 3.1 | 0.858 | True |
| netfound | nfm | CPU+GPU | 22.8 | 23.7 | 1024 | 10.2 | 4.1 | 0.813 | False |

**Pareto-optimal:** nfstream-common, nfstream-native, yatc, etbert.
