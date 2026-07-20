# Actual Framework Metrics

## Experiment identity

- Comparison ID: `final-20260720-seed20260720-v1`
- Random seed: `20260720`
- Paired cohort: 1,016 sessions, with one result from each framework for every session
- Class distribution: 844 malicious and 172 benign sessions
- Decision policy for proposed and ablation: step-up at risk >= 0.24; deny at risk >= 0.75
- Latency statistics exclude the first five warm-up decisions per framework (n = 1,011)

## Security results

| Framework | TP | TN | FP | FN | TPR (95% CI) | FPR (95% CI) | Precision (95% CI) | F1 | Accuracy (95% CI) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Proposed | 325 | 167 | 5 | 519 | 38.51% (35.28–41.84%) | 2.91% (1.25–6.62%) | 98.48% (96.50–99.35%) | 0.5537 | 48.43% (45.36–51.50%) |
| Ablation | 291 | 172 | 0 | 553 | 34.48% (31.35–37.75%) | 0.00% (0.00–2.18%) | 100.00% (98.70–100.00%) | 0.5128 | 45.57% (42.53–48.64%) |
| Ahmadi (2025) | 165 | 159 | 13 | 679 | 19.55% (17.01–22.36%) | 7.56% (4.47–12.50%) | 92.70% (87.91–95.68%) | 0.3229 | 31.89% (29.10–34.82%) |
| Phani Kumar Kanuri (2025) | 91 | 168 | 4 | 753 | 10.78% (8.86–13.05%) | 2.33% (0.91–5.83%) | 95.79% (89.67–98.35%) | 0.1938 | 25.49% (22.91–28.26%) |

The proposed framework's paired correctness improvement over ablation is statistically significant but modest (McNemar chi-square = 5.9847, p = 0.01443). Comparisons with Ahmadi and Phani are also significant (p < 0.0001 at the stored precision).

## ROC results

| Framework | Exact AUC |
|---|---:|
| Proposed | 0.8096 |
| Ahmadi (2025) | 0.5526 |
| Phani Kumar Kanuri (2025) | 0.5560 |

The unconstrained F1 optimum is threshold 0.0 for all three scores because the cohort is 83.07% malicious. That value is not an operational threshold recommendation; threshold selection must include a false-positive or usability constraint.

## Benign-session usability

| Framework | Benign n | Allow | Step-up | Deny | Any friction |
|---|---:|---:|---:|---:|---:|
| Proposed | 172 | 167 | 5 | 0 | 2.91% |
| Ablation | 172 | 172 | 0 | 0 | 0.00% |
| Ahmadi (2025) | 172 | 159 | 9 | 4 | 7.56% |
| Phani Kumar Kanuri (2025) | 172 | 168 | 0 | 4 | 2.33% |

## End-to-end latency

| Framework | Mean | Median | p95 | p99 |
|---|---:|---:|---:|---:|
| Proposed | 755.3 ms | 189 ms | 2,491.5 ms | 2,692.6 ms |
| Ablation | 159.7 ms | 153 ms | 191.0 ms | 283.8 ms |
| Ahmadi (2025) | 10.7 ms | 11 ms | 14.0 ms | 20.0 ms |
| Phani Kumar Kanuri (2025) | 9.6 ms | 9 ms | 12.0 ms | 19.9 ms |

These are client-observed end-to-end times. The proposed pipeline is materially slower because it performs validation, enrichment, cross-checking, persistence, gateway handling, and trust evaluation across multiple services.

## STRIDE detection results

| Category | Proposed | Ablation | Ahmadi | Phani |
|---|---:|---:|---:|---:|
| Spoofing | 29.30% | 0.00% | 65.61% | 44.59% |
| Tampering | 20.16% | 0.00% | 6.20% | 0.78% |
| Repudiation | 26.83% | 51.22% | 12.20% | 4.88% |
| Information Disclosure | 1.43% | 0.00% | 5.00% | 2.14% |
| Denial of Service | 99.44% | 99.44% | 11.30% | 5.08% |
| Elevation of Privilege | 33.33% | 45.91% | 10.69% | 2.52% |

The validation/enrichment layer creates clear gains for Tampering and Spoofing. However, quality/confidence scaling reduces risk enough that ablation detects more Repudiation and EoP cases. Information Disclosure remains an unresolved detector/signal gap. These negative findings must be retained in the thesis.

## Interpretation constraints

- Proposed and ablation produced no deny decisions at the configured 0.75 threshold, so deny-path effectiveness is not established by this run.
- The SIEM data records and categorizes alerts, but this one-shot unique-session design does not isolate the causal contribution of SIEM feedback to later decisions.
- Network-condition sensitivity was not measured in this exact comparison run and is deliberately omitted.
- Jimmy (2025) is not included quantitatively because a reproducible scoring equation was not available in the supplied implementation basis.
- These results replace earlier hardcoded or stale Chapter 4 values; they should not be mixed with a different comparison ID.

Machine-readable sources: `chapter4_metrics.json`, `roc_data.json`, and `experiment_manifest.json` in this directory.
