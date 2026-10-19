# ITBench scenarios (synthetic snapshots), test split, 3 runs each

ITBench-AA scoring: a run scores 0 if any ground-truth root cause is missed, otherwise its precision. `strict` needs the exact kind and name; `component` lets a Deployment, its Pods and its Service stand for each other, as the ITBench judge's semantic grouping does.

## test (15 scenarios, 45 runs)

| method | ITBench score (strict) | ITBench score (component) | all root causes found | precision | entities / run | scenarios solved | p50 latency |
|---|---:|---:|---:|---:|---:|---:|---:|
| alert targets (baseline) | 0.241 | 0.241 | 53% | 0.34 | 4.47 | 0/15 | 34 ms |
| error origin (baseline) | 0.200 | 0.200 | 20% | 0.33 | 1 | 3/15 | 36 ms |
| every anomaly (baseline) | 0.290 | 0.290 | 73% | 0.39 | 3.47 | 0/15 | 32 ms |
| rules engine | 1.000 | 1.000 | 100% | 1.00 | 1.67 | 15/15 | 34 ms |

## all (15 scenarios, 45 runs)

| method | ITBench score (strict) | ITBench score (component) | all root causes found | precision | entities / run | scenarios solved | p50 latency |
|---|---:|---:|---:|---:|---:|---:|---:|
| alert targets (baseline) | 0.241 | 0.241 | 53% | 0.34 | 4.47 | 0/15 | 34 ms |
| error origin (baseline) | 0.200 | 0.200 | 20% | 0.33 | 1 | 3/15 | 36 ms |
| every anomaly (baseline) | 0.290 | 0.290 | 73% | 0.39 | 3.47 | 0/15 | 32 ms |
| rules engine | 1.000 | 1.000 | 100% | 1.00 | 1.67 | 15/15 | 34 ms |

## Per scenario: rules engine

| scenario | split | ground truth | prediction (first run) | strict | component |
|---|---|---|---|---:|---:|
| 23 | test | otel-demo/Deployment/checkout | otel-demo/Deployment/checkout | 1.00 | 1.00 |
| 31 | test | otel-demo/Deployment/frontend, otel-demo/NetworkPolicy/frontend-ingress | otel-demo/NetworkPolicy/frontend-ingress, otel-demo/Deployment/frontend | 1.00 | 1.00 |
| 33 | test | otel-demo/Deployment/ad, otel-demo/Deployment/cart | otel-demo/Deployment/ad, otel-demo/Deployment/cart | 1.00 | 1.00 |
| 38 | test | otel-demo/HorizontalPodAutoscaler/fraud-detection, otel-demo/HorizontalPodAutoscaler/frontend, otel-demo/HorizontalPodAutoscaler/image-provider | otel-demo/HorizontalPodAutoscaler/fraud-detection, otel-demo/HorizontalPodAutoscaler/frontend, otel-demo/HorizontalPodAutoscaler/image-provider | 1.00 | 1.00 |
| 39 | test | otel-demo/Deployment/payment | otel-demo/Deployment/payment | 1.00 | 1.00 |
| 42 | test | otel-demo/Deployment/kafka | otel-demo/Deployment/kafka | 1.00 | 1.00 |
| 46 | test | otel-demo/Deployment/postgresql | otel-demo/Deployment/postgresql | 1.00 | 1.00 |
| 47 | test | book-info/Gateway/bookinfo-gateway, book-info/AuthorizationPolicy/bookinfo-gateway-policy | book-info/AuthorizationPolicy/bookinfo-gateway-policy, book-info/Gateway/bookinfo-gateway | 1.00 | 1.00 |
| 50 | test | book-info/Deployment/productpage-v1, book-info/PeerAuthentication/application | book-info/PeerAuthentication/application, book-info/Deployment/productpage-v1 | 1.00 | 1.00 |
| 53 | test | book-info/Deployment/reviews-v3 | book-info/Deployment/reviews-v3 | 1.00 | 1.00 |
| 57 | test | otel-demo/Deployment/checkout | otel-demo/Deployment/checkout | 1.00 | 1.00 |
| 59 | test | otel-demo/Deployment/recommendation, otel-demo/ConfigMap/recommendation-config | otel-demo/Deployment/recommendation, otel-demo/ConfigMap/recommendation-config | 1.00 | 1.00 |
| 60 | test | otel-demo/Deployment/recommendation, otel-demo/ConfigMap/recommendation-config, otel-demo/Deployment/checkout | otel-demo/Deployment/checkout, otel-demo/Deployment/recommendation, otel-demo/ConfigMap/recommendation-config | 1.00 | 1.00 |
| 63 | test | otel-demo/Secret/email-service-secret | otel-demo/Secret/email-service-secret | 1.00 | 1.00 |
| 102 | test | otel-demo/Deployment/ad, otel-demo/ResourceQuota/strict-resource-quota | otel-demo/ResourceQuota/strict-resource-quota, otel-demo/Deployment/ad | 1.00 | 1.00 |
