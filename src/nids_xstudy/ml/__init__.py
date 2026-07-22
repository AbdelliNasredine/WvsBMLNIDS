"""ML pipeline (Phase 3): datasets, feature regimes, models, training, eval.

The extractor is the only independent variable — every tool's labeled canonical
flows go through one shared pipeline. Two feature regimes:
  * R-common: harmonized core features available across all tools (duration,
    per-direction packet/byte counts, protocol) — for cross-tool comparability.
  * R-native: the tool's full native feature vector — what a practitioner gets.
"""
