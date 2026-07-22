#!/usr/bin/env python
"""Phase B5.2: unsupervised / zero-shot anomaly detection. Train ONLY on benign
flows (no attack labels), score test flows, and measure attack detection
(AUC-ROC / AUC-PR) per extractor + detector. NFM embeddings vs NFStream
hand-engineered features on the identical flows -- the honest 'zero-shot' test.

Each extractor's features are standardized + PCA-reduced (fit on benign train)
to a common 32-dim space so detectors are tractable and comparable across the
128..9216-dim representations (documented preprocessing).

    python scripts/blackbox/run_b5_anomaly.py    # nids-xstudy env
-> results/metrics_bb/b5_anomaly.csv
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.covariance import LedoitWolf  # noqa: E402
from sklearn.decomposition import PCA  # noqa: E402
from sklearn.metrics import average_precision_score, roc_auc_score  # noqa: E402
from sklearn.neighbors import NearestNeighbors  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sklearn.svm import OneClassSVM  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.ml.dataset import split_mask  # noqa: E402
from run_b2_grid import load_nfm  # noqa: E402
from run_b5_kshot import EXTRACTORS, labels_and_caps  # noqa: E402

NCOMP = 32
OCSVM_CAP = 5000


def score_all(Ztr, Zte, seed):
    out = {}
    nn = NearestNeighbors(n_neighbors=5).fit(Ztr)
    out["knn"] = nn.kneighbors(Zte)[0].mean(axis=1)
    lw = LedoitWolf().fit(Ztr)
    out["mahalanobis"] = lw.mahalanobis(Zte)
    rng = np.random.default_rng(seed)
    sub = Ztr if len(Ztr) <= OCSVM_CAP else Ztr[rng.choice(len(Ztr), OCSVM_CAP, replace=False)]
    oc = OneClassSVM(nu=0.1, gamma="scale").fit(sub)
    out["ocsvm"] = -oc.decision_function(Zte)  # higher = more anomalous
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="cicids2017")
    args = ap.parse_args()
    ds = args.dataset
    ym, caps = labels_and_caps(ds)
    dfcap = pd.DataFrame({"_capture": caps})
    tr_pool, te = split_mask(dfcap, ym, "stratified", 999, dataset=ds)
    te_idx = np.where(te)[0]
    benign_tr = np.where(tr_pool & (ym == "BENIGN"))[0]
    y_attack = (ym[te_idx] != "BENIGN").astype(int)
    print(f"benign_train={len(benign_tr)} test={len(te_idx)} attack_frac={y_attack.mean():.3f}")

    rows = []
    for model in EXTRACTORS:
        X = load_nfm(model, ds)[0]
        Xtr, Xte = X[benign_tr], X[te_idx]
        from sklearn.impute import SimpleImputer
        imp = SimpleImputer(strategy="median", keep_empty_features=True).fit(Xtr)
        Xtr, Xte = imp.transform(Xtr), imp.transform(Xte)
        sc = StandardScaler().fit(Xtr)
        nc = min(NCOMP, Xtr.shape[1])
        pca = PCA(nc, svd_solver="randomized", random_state=0).fit(sc.transform(Xtr))
        Ztr = pca.transform(sc.transform(Xtr)); Zte = pca.transform(sc.transform(Xte))
        scores = score_all(Ztr, Zte, 0)
        for det, sc_v in scores.items():
            rows.append({"extractor": model, "detector": det,
                         "auc_roc": float(roc_auc_score(y_attack, sc_v)),
                         "auc_pr": float(average_precision_score(y_attack, sc_v))})
        best = max(rows[-3:], key=lambda r: r["auc_pr"])
        print(f"[ok] {model}: best {best['detector']} AUC-PR={best['auc_pr']:.3f} "
              f"ROC={best['auc_roc']:.3f}", flush=True)
    out = cfg.results_dir() / "metrics_bb" / ds / "b5_anomaly.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(out, index=False)
    print(f"wrote {out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
