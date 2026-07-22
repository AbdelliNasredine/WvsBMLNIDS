"""Cross-tool flow alignment (Phase 2 / RQ3).

Match flows between two tools by order-independent 5-tuple + temporal overlap,
and classify each flow as 1:1, split (one flow <-> many), merge (many <-> one),
or unmatched. This quantifies how much tools disagree on the *unit of analysis*.
"""
from .align import bidir_key_series, match_pair, CATEGORIES  # noqa: F401
