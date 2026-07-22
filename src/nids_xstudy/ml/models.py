"""Model factory + preprocessing pipeline (median impute, 1/99 clip, standardize).

Preprocessing is fit on the training split only. Clipping/standardization are
harmless for trees and necessary for LogReg/MLP, so the same pipeline is used
for every model for consistency.
"""
from __future__ import annotations

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler


def _inf_to_nan(X):
    """Replace +/-inf with NaN so imputation can fill it (some native features,
    e.g. bytes/s on 0-duration flows, are infinite)."""
    X = np.asarray(X, dtype="float64").copy()
    X[~np.isfinite(X)] = np.nan
    return X

MODELS = ["rf", "xgb", "logreg", "mlp"]


class QuantileClipper(BaseEstimator, TransformerMixin):
    """Clip each feature to its [lo, hi] train quantiles (heavy-tail control)."""

    def __init__(self, lo: float = 0.01, hi: float = 0.99):
        self.lo, self.hi = lo, hi

    def fit(self, X, y=None):
        X = np.asarray(X, dtype="float64")
        self.lo_ = np.nanpercentile(X, self.lo * 100, axis=0)
        self.hi_ = np.nanpercentile(X, self.hi * 100, axis=0)
        return self

    def transform(self, X):
        return np.clip(np.asarray(X, dtype="float64"), self.lo_, self.hi_)


def _estimator(name: str, seed: int):
    if name == "rf":
        from sklearn.ensemble import RandomForestClassifier
        return RandomForestClassifier(
            n_estimators=200, max_depth=None, n_jobs=-1,
            class_weight="balanced_subsample", random_state=seed)
    if name == "xgb":
        from xgboost import XGBClassifier
        return XGBClassifier(
            n_estimators=300, max_depth=8, learning_rate=0.1, subsample=0.9,
            colsample_bytree=0.9, tree_method="hist", n_jobs=-1,
            random_state=seed, eval_metric="mlogloss")
    if name == "logreg":
        from sklearn.linear_model import LogisticRegression
        return LogisticRegression(
            max_iter=2000, class_weight="balanced", n_jobs=-1, random_state=seed)
    if name == "mlp":
        from sklearn.neural_network import MLPClassifier
        return MLPClassifier(
            hidden_layer_sizes=(64, 32), max_iter=80, early_stopping=True,
            random_state=seed)
    raise ValueError(f"unknown model {name!r}")


def make_pipeline(name: str, seed: int) -> Pipeline:
    return Pipeline([
        ("inf", FunctionTransformer(_inf_to_nan)),
        ("impute", SimpleImputer(strategy="median")),
        ("clip", QuantileClipper(0.01, 0.99)),
        ("scale", StandardScaler()),
        ("clf", _estimator(name, seed)),
    ])
