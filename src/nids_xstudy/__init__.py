"""nids_xstudy — tooling for the NIDS feature-extractor impact study.

Subpackages
-----------
extraction    per-tool PCAP -> canonical-parquet runners
labeling      single shared traffic-level ground-truth labeling engine
harmonize     common-feature mapping across tools (Phase 3)
flow_alignment cross-tool flow matching + divergence metrics (Phase 2)
ml            datasets, splits, models, training, eval (Phase 3)
analysis      stats tests, tables, figures (Phase 5)
"""

__version__ = "0.1.0"
