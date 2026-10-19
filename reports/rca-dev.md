# ITBench scenarios (synthetic snapshots), dev split, 3 runs each

ITBench-AA scoring: a run scores 0 if any ground-truth root cause is missed, otherwise its precision. `strict` needs the exact kind and name; `component` lets a Deployment, its Pods and its Service stand for each other, as the ITBench judge's semantic grouping does.

## dev (15 scenarios, 45 runs)

| method | ITBench score (strict) | ITBench score (component) | all root causes found | precision | entities / run | scenarios solved | p50 latency |
|---|---:|---:|---:|---:|---:|---:|---:|
| alert targets (baseline) | 0.293 | 0.316 | 67% | 0.29 | 4.33 | 0/15 | 34 ms |
| error origin (baseline) | 0.422 | 0.422 | 42% | 0.42 | 1 | 6/15 | 37 ms |
| every anomaly (baseline) | 0.289 | 0.289 | 87% | 0.29 | 2.93 | 0/15 | 34 ms |
| rules engine | 0.933 | 0.933 | 93% | 0.93 | 1 | 14/15 | 33 ms |

## all (15 scenarios, 45 runs)

| method | ITBench score (strict) | ITBench score (component) | all root causes found | precision | entities / run | scenarios solved | p50 latency |
|---|---:|---:|---:|---:|---:|---:|---:|
| alert targets (baseline) | 0.293 | 0.316 | 67% | 0.29 | 4.33 | 0/15 | 34 ms |
| error origin (baseline) | 0.422 | 0.422 | 42% | 0.42 | 1 | 6/15 | 37 ms |
| every anomaly (baseline) | 0.289 | 0.289 | 87% | 0.29 | 2.93 | 0/15 | 34 ms |
| rules engine | 0.933 | 0.933 | 93% | 0.93 | 1 | 14/15 | 33 ms |

## Per scenario: rules engine

| scenario | split | ground truth | prediction (first run) | strict | component |
|---|---|---|---|---:|---:|
| 20 | dev | otel-demo/Deployment/product-catalog | otel-demo/Deployment/product-catalog | 1.00 | 1.00 |
| 30 | dev | otel-demo/Service/ad | otel-demo/Service/ad | 1.00 | 1.00 |
| 34 | dev | otel-demo/Deployment/valkey-cart | otel-demo/Secret/valkey-credentials | 0.00 | 0.00 |
| 36 | dev | book-info/Service/details | book-info/Service/details | 1.00 | 1.00 |
| 40 | dev | otel-demo/Service/valkey-cart | otel-demo/Service/valkey-cart | 1.00 | 1.00 |
| 43 | dev | otel-demo/Deployment/frontend | otel-demo/Deployment/frontend | 1.00 | 1.00 |
| 44 | dev | otel-demo/Deployment/payment | otel-demo/Deployment/payment | 1.00 | 1.00 |
| 45 | dev | otel-demo/Deployment/email | otel-demo/Deployment/email | 1.00 | 1.00 |
| 48 | dev | /Namespace/book-info | /Namespace/book-info | 1.00 | 1.00 |
| 49 | dev | otel-demo/Deployment/frontend | otel-demo/Deployment/frontend | 1.00 | 1.00 |
| 56 | dev | otel-demo/Deployment/product-catalog | otel-demo/Deployment/product-catalog | 1.00 | 1.00 |
| 58 | dev | otel-demo/Deployment/accounting | otel-demo/Deployment/accounting | 1.00 | 1.00 |
| 105 | dev | otel-demo/Deployment/product-catalog | otel-demo/Deployment/product-catalog | 1.00 | 1.00 |
| 114 | dev | otel-demo/Service/product-catalog | otel-demo/Service/product-catalog | 1.00 | 1.00 |
| 116 | dev | otel-demo/Deployment/frontend | otel-demo/Deployment/frontend | 1.00 | 1.00 |
