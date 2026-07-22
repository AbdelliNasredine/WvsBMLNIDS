# Significance tests

## binary / stratified
Friedman χ²=134.5, p=3.31e-25 (k=9 tools, 40 blocks). Lower avg rank = better.

avg ranks: **cicflowmeter-fixed** 2.08, **tranalyzer** 2.42, **cicflowmeter-orig** 4.30, **zeek** 4.90, **yaf** 5.58, **nfstream** 5.80, **argus** 6.30, **joy** 6.42, **go-flows** 7.20

## binary / temporal
Friedman χ²=73.7, p=8.90e-13 (k=9 tools, 40 blocks). Lower avg rank = better.

avg ranks: **cicflowmeter-orig** 2.98, **tranalyzer** 3.77, **yaf** 4.10, **go-flows** 4.88, **cicflowmeter-fixed** 5.05, **nfstream** 5.30, **joy** 5.58, **zeek** 5.85, **argus** 7.50

## multiclass / stratified
Friedman χ²=165.2, p=1.33e-31 (k=9 tools, 40 blocks). Lower avg rank = better.

avg ranks: **tranalyzer** 2.05, **zeek** 2.73, **cicflowmeter-fixed** 3.55, **argus** 3.80, **nfstream** 5.90, **yaf** 6.42, **joy** 6.47, **cicflowmeter-orig** 6.70, **go-flows** 7.38

## RQ4: CICFlowMeter orig vs fixed (Wilcoxon signed-rank)
n=120 paired configs; fixed wins 90/120; median Δ(fixed−orig)=0.0421; W=1744.0, p=7.84e-07.

## H4: model-ranking stability across extractors (multiclass, R-common)
Mean Kendall τ between tools' model-rankings = **0.926** (min 0.667). τ≈1 would mean identical model rankings; lower τ means the best *model* depends on the extractor.

