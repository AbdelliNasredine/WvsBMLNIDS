"""Load Phase-3 metrics and run Phase-5 statistics.

* variance_decomposition — ANOVA-style share of macro-F1 variance per factor
  (the headline: extractor explains X% vs model Y%), within a (task, split) cell.
* friedman_nemenyi — Friedman test over tools (blocks = model×regime×seed) with
  average ranks + Nemenyi post-hoc (for a critical-difference diagram).
* wilcoxon_pair — paired Wilcoxon signed-rank for the orig-vs-fixed comparison.
* kendall_tau_model_ranking — H4: are model rankings stable across extractors?
"""
from __future__ import annotations

import json
from itertools import combinations

import numpy as np
import pandas as pd
from scipy import stats

from .. import config as cfg


def load_metrics(dataset: str = "cicids2017") -> tuple[pd.DataFrame, pd.DataFrame]:
    summary, perclass = [], []
    for f in (cfg.results_dir() / "metrics" / dataset).glob("*.json"):
        r = json.loads(f.read_text(encoding="utf-8"))
        c, m = r["config"], r["metrics"]
        base = {k: c.get(k) for k in ("tool", "regime", "model", "task", "split", "seed")}
        summary.append({**base, "macro_f1": m["macro_f1"], "weighted_f1": m["weighted_f1"],
                        "balanced_acc": m["balanced_accuracy"], "fpr": m.get("fpr"),
                        "auc_pr": m.get("auc_pr")})
        for cls, d in m.get("per_class", {}).items():
            if cls in ("accuracy", "macro avg", "weighted avg", "<unseen>"):
                continue
            perclass.append({**base, "class": cls, "recall": d["recall"], "f1": d["f1-score"]})
    return pd.DataFrame(summary), pd.DataFrame(perclass)


def variance_decomposition(df: pd.DataFrame, task: str, split: str) -> dict:
    """% of macro-F1 variance explained by each factor (type-II ANOVA SS)."""
    import statsmodels.api as sm
    from statsmodels.formula.api import ols
    sub = df[(df.task == task) & (df.split == split)].copy()
    if sub["tool"].nunique() < 2 or len(sub) < 10:
        return {}
    sub = sub.rename(columns={"macro_f1": "y"})
    factors = [f for f in ["tool", "model", "regime", "seed"] if sub[f].nunique() > 1]
    formula = "y ~ " + " + ".join(f"C({f})" for f in factors)
    model = ols(formula, data=sub).fit()
    aov = sm.stats.anova_lm(model, typ=2)
    ss_total = aov["sum_sq"].sum()
    out = {f: round(100 * aov.loc[f"C({f})", "sum_sq"] / ss_total, 1) for f in factors}
    out["residual"] = round(100 * aov.loc["Residual", "sum_sq"] / ss_total, 1)
    return out


def friedman_nemenyi(df: pd.DataFrame, task: str, split: str):
    """Friedman over tools; blocks = (model, regime, seed). Returns (stat, p, ranks, nemenyi)."""
    import scikit_posthocs as sp
    sub = df[(df.task == task) & (df.split == split)]
    piv = sub.pivot_table(index=["model", "regime", "seed"], columns="tool", values="macro_f1")
    piv = piv.dropna(axis=0, how="any")
    if piv.shape[0] < 3 or piv.shape[1] < 3:
        return None
    stat, p = stats.friedmanchisquare(*[piv[c].to_numpy() for c in piv.columns])
    # average ranks (higher macro-F1 = rank 1)
    ranks = piv.rank(axis=1, ascending=False).mean(axis=0).sort_values()
    nem = sp.posthoc_nemenyi_friedman(piv.to_numpy())
    nem.index = nem.columns = piv.columns
    return {"stat": float(stat), "p": float(p), "ranks": ranks, "nemenyi": nem,
            "n_blocks": int(piv.shape[0]), "k_tools": int(piv.shape[1])}


def wilcoxon_pair(df, a="cicflowmeter-orig", b="cicflowmeter-fixed"):
    """Paired Wilcoxon over matched (regime, model, task, split, seed) configs."""
    keys = ["regime", "model", "task", "split", "seed"]
    A = df[df.tool == a].set_index(keys)["macro_f1"]
    B = df[df.tool == b].set_index(keys)["macro_f1"]
    common = A.index.intersection(B.index)
    a_v, b_v = A.loc[common].to_numpy(), B.loc[common].to_numpy()
    if len(common) < 5:
        return None
    stat, p = stats.wilcoxon(b_v, a_v)
    return {"n_pairs": int(len(common)), "stat": float(stat), "p": float(p),
            "median_delta_fixed_minus_orig": float(np.median(b_v - a_v)),
            "wins_fixed": int((b_v > a_v).sum())}


def kendall_tau_model_ranking(df, task: str, split: str, regime: str = "common"):
    """H4: rank models within each tool; Kendall tau between tools' rankings."""
    sub = df[(df.task == task) & (df.split == split) & (df.regime == regime)]
    piv = sub.groupby(["tool", "model"])["macro_f1"].mean().unstack("model")
    if piv.shape[0] < 2 or piv.shape[1] < 2:
        return None
    tools = list(piv.index)
    taus = []
    for a, b in combinations(tools, 2):
        t, _ = stats.kendalltau(piv.loc[a].rank(), piv.loc[b].rank())
        if not np.isnan(t):
            taus.append(t)
    return {"mean_tau": float(np.mean(taus)) if taus else float("nan"),
            "min_tau": float(np.min(taus)) if taus else float("nan"),
            "rankings": piv.rank(axis=1, ascending=False)}
