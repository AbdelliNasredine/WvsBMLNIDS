# Significance tests

## binary / stratified
Friedman χ²=176.4, p=5.90e-34 (k=9 tools, 40 blocks). Lower avg rank = better.

avg ranks: **tranalyzer** 1.75, **nfstream** 3.48, **zeek** 3.60, **argus** 3.98, **cicflowmeter-fixed** 4.60, **go-flows** 5.78, **cicflowmeter-orig** 6.65, **joy** 7.20, **yaf** 7.97

## binary / temporal
Friedman χ²=150.0, p=1.99e-28 (k=9 tools, 40 blocks). Lower avg rank = better.

avg ranks: **tranalyzer** 2.98, **yaf** 3.42, **joy** 3.77, **cicflowmeter-fixed** 4.05, **zeek** 4.15, **cicflowmeter-orig** 5.70, **nfstream** 5.78, **go-flows** 6.15, **argus** 9.00

## multiclass / stratified
Friedman χ²=106.0, p=2.52e-19 (k=9 tools, 40 blocks). Lower avg rank = better.

avg ranks: **cicflowmeter-fixed** 2.65, **tranalyzer** 2.98, **argus** 4.12, **nfstream** 4.78, **zeek** 4.97, **joy** 5.65, **cicflowmeter-orig** 5.75, **yaf** 6.90, **go-flows** 7.20

## RQ4: CICFlowMeter orig vs fixed (Wilcoxon signed-rank)
n=120 paired configs; fixed wins 105/120; median Δ(fixed−orig)=0.0431; W=604.0, p=2.29e-15.

## H4: model-ranking stability across extractors (multiclass, R-common)
Mean Kendall τ between tools' model-rankings = **0.870** (min 0.667). τ≈1 would mean identical model rankings; lower τ means the best *model* depends on the extractor.

