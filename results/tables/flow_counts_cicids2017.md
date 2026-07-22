# Cross-tool flow counts — cicids2017

Total flows per capture per extractor (reference = nfstream). Ratios far
from 1 indicate flow-accounting divergence; expect the largest
divergence on attack-heavy captures (RQ3 / H3).

| capture | nfstream | zeek | cicflowmeter-orig | tranalyzer | zeek/nfstream | cicflowmeter-orig/nfstream | tranalyzer/nfstream |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Monday | 355732 | 375412 |  | 353711 | 1.055 |  | 0.994 |
| Tuesday | 308349 | 323325 | 386846.0 | 305359 | 1.049 | 1.255 | 0.99 |
| Wednesday | 337293 | 509349 |  | 479256 | 1.51 |  | 1.421 |
| Thursday | 343134 | 363760 |  | 341395 | 1.06 |  | 0.995 |
| Friday | 501096 | 547334 |  | 534147 | 1.092 |  | 1.066 |

