"""Reference flow assembler for the black-box (NFM) study.

Black-box models consume per-flow *packet sequences*, so a flow-segmentation
decision must be made before any neural network sees the traffic. That decision
is a white-box choice hiding inside every black-box pipeline; we make it explicit
and ablatable here (plan section 3, RQ-B3). The reference policy mirrors the
white-box study's canonical segmentation: order-independent bidirectional
5-tuple, 120 s idle / 1800 s active timeouts.

The assembler emits one row per flow with (a) the canonical flow key + timestamps
(so the EXISTING traffic-level labeling engine labels it unchanged) and (b) the
first ``max_pkts`` packets' first ``max_bytes`` IP-layer bytes as a padded
uint8 image, plus per-packet direction/time/size. Per-model input builders
(src/nids_xstudy/nfm) convert this common intermediate to each model's format.
"""
from .assembler import ASSEMBLY_DEFAULTS, AssemblyConfig, assemble

__all__ = ["assemble", "AssemblyConfig", "ASSEMBLY_DEFAULTS"]
