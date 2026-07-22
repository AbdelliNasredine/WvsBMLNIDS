"""Single shared, traffic-level ground-truth labeling engine.

The label is a property of the *traffic*, computed identically for every tool's
canonical flows from one rules file — never taken from tool-shipped labels. This
is the core of the study's internal validity (plan section 5).
"""
from .engine import LabelRules, label_flows, class_distribution  # noqa: F401
