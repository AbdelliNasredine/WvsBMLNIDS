# RQ5 cross-dataset generalization (binary macro-F1, RF head)

Train on the SOURCE dataset's 70% (R-common features for white-box tools;
frozen sample embeddings for NFMs), evaluate in-distribution (source test)
and cross-dataset (all of the target). Mean over 5 seeds.

For each direction, the in-dist minus cross gap is the generalization
collapse; H5 asks whether that collapse depends on the extractor.

| family | extractor | CIC in-dist | CIC→DAPT | DAPT in-dist | DAPT→CIC | mean collapse |
| --- | --- | --- | --- | --- | --- | --- |
| hand-engineered | nfstream-common | 0.995 | 0.476 | 0.856 | 0.431 | 0.472 |
| nfm | etbert | 0.962 | 0.666 | 0.838 | 0.419 | 0.358 |
| nfm | netfound | 0.998 | 0.679 | 0.907 | 0.297 | 0.465 |
| nfm | raw-cnn | 0.989 | 0.552 | 0.884 | 0.306 | 0.508 |
| nfm | yatc | 0.993 | 0.635 | 0.885 | 0.399 | 0.422 |
| white-box | argus | 0.994 | 0.469 | 0.892 | 0.454 | 0.482 |
| white-box | cicflowmeter-fixed | 0.985 | 0.434 | 0.949 | 0.572 | 0.464 |
| white-box | cicflowmeter-orig | 0.966 | 0.535 | 0.841 | 0.717 | 0.277 |
| white-box | go-flows | 0.914 | 0.462 | 0.845 | 0.621 | 0.338 |
| white-box | joy | 0.983 | 0.520 | 0.855 | 0.734 | 0.292 |
| white-box | nfstream | 0.994 | 0.477 | 0.856 | 0.657 | 0.358 |
| white-box | tranalyzer | 0.990 | 0.481 | 0.898 | 0.560 | 0.423 |
| white-box | yaf | 0.915 | 0.456 | 0.849 | 0.604 | 0.352 |
| white-box | zeek | 0.983 | 0.466 | 0.889 | 0.642 | 0.382 |

