#!/usr/bin/env python
"""Map the shared 142k-flow sample to a white-box tool's hand-engineered features,
so the SAME flows can be compared to the NFM embeddings under the identical B2
grid (the controlled RQ-B2 comparison). The reference assembler ~= NFStream
(exact flow counts), so NFStream maps ~1:1; each sampled flow is matched to the
tool flow with the same bidirectional key and nearest t_start.

Writes feature matrices aligned to the sample as pseudo-'embeddings':
  embeddings_dir('<tool>-common','sample')/<cap>.npy   (R-common features)
  embeddings_dir('<tool>-native','sample')/<cap>.npy   (R-native features)
so run_b2_grid.py can treat '<tool>-common' / '<tool>-native' as extractors.
Run in the nids-xstudy env.
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from nids_xstudy import config as cfg  # noqa: E402
from nids_xstudy.assembly.assembler import _bidir_key  # noqa: E402
from nids_xstudy.ml import dataset as D  # noqa: E402


def _bk(df):
    return [_bidir_key(r.src_ip, r.src_port, r.dst_ip, r.dst_port, r.proto)
            for r in df.itertuples()]


def main(tools=("nfstream",), dataset="cicids2017"):
    sdir = cfg.assembled_dir(dataset, "sample")
    for tool in tools:
        # fixed native column set from the full tool data (constant-column drop
        # otherwise varies per day -> inconsistent dims across captures).
        full = pd.concat([pd.read_parquet(cfg.labeled_dir(dataset, tool) / f"{c}.parquet")
                          for c in cfg.captures(dataset)], ignore_index=True)
        native_cols = D.feature_matrix(full, "native")[1]
        del full
        for cap in cfg.captures(dataset):
            smeta = pd.read_parquet(sdir / f"{cap}.meta.parquet")
            tdf = pd.read_parquet(cfg.labeled_dir(dataset, tool) / f"{cap}.parquet").reset_index(drop=True)
            # index tool flows by bidir key -> [(t_start, row)]
            by_key = defaultdict(list)
            for i, (k, ts) in enumerate(zip(_bk(tdf), tdf["t_start"].to_numpy())):
                by_key[k].append((float(ts), i))
            # nearest-t_start match for each sampled flow
            skeys = _bk(smeta); sts = smeta["t_start"].to_numpy()
            match = np.full(len(smeta), -1, dtype=np.int64)
            for j, (k, ts) in enumerate(zip(skeys, sts)):
                cand = by_key.get(k)
                if cand:
                    match[j] = min(cand, key=lambda c: abs(c[0] - ts))[1]
            miss = int((match < 0).sum())
            # gather matched tool rows aligned to sample order (missing -> a NaN row)
            safe = np.where(match < 0, 0, match)
            matched = tdf.iloc[safe].reset_index(drop=True)
            common = D.feature_matrix(matched, "common")[0].to_numpy("float32")
            native = (matched.reindex(columns=native_cols).apply(pd.to_numeric, errors="coerce")
                      .to_numpy("float32"))
            for regime, Xnp in [("common", common), ("native", native)]:
                Xnp = Xnp.copy(); Xnp[match < 0] = np.nan  # unmatched -> imputed downstream
                np.save(cfg.embeddings_dir(dataset, f"{tool}-{regime}", "sample") / f"{cap}.npy", Xnp)
            print(f"[ok] {tool} {cap}: matched {len(smeta)-miss}/{len(smeta)} "
                  f"(miss={miss}) common={common.shape[1]} native={native.shape[1]}", flush=True)
    print("MAP DONE", flush=True)


if __name__ == "__main__":
    main()
