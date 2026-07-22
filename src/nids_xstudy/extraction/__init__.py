"""Per-tool extraction runners: PCAP -> raw tool output -> canonical parquet.

Each runner writes:
  * a canonical parquet at ``config.canonical_dir(dataset, tool)/<capture>.parquet``
  * a sidecar ``<capture>.meta.json`` recording tool version, config, versions,
    git commit and a pcap fingerprint (see :mod:`nids_xstudy.extraction.base`).
"""
