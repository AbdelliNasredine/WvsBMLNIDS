"""Single shared, traffic-level ground-truth labeling engine.

The label is a property of the *traffic*, computed identically for every tool's
canonical flows from one rules file — never taken from tool-shipped labels. This
is the core of the study's internal validity (plan section 5).
"""
from .engine import LabelRules, label_flows, class_distribution  # noqa: F401


def label_dataset(df, dataset, cfg, capture=None, rules_path=None):
    """Label ``df`` with ``dataset``'s rules (capture-scoped where a rule sets
    ``capture:``), plus the DAPT hybrid recon projection when a
    ``recon_flows.parquet`` reference exists (dataset-agnostic: a no-op for
    datasets without one, e.g. cicids2017)."""
    from .dapt_recon import apply_recon, load_recon_ref, recon_ref_path
    rules = LabelRules.load(rules_path or cfg.rules_path(dataset))
    out = label_flows(df, rules, capture=capture)
    ref = recon_ref_path(dataset, cfg)
    if ref is not None:
        out = apply_recon(out, load_recon_ref(ref, capture=capture))
    return out
