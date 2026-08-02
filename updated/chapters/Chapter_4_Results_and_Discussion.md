# Chapter 4: Results and Discussion

## 4.0 Overview

This chapter presents the experimental results of the proposed multi-source context validation framework and benchmarks it against the ablation configuration (proposed pipeline with the validation layer's enrichment step removed, Section 3.2.7), and two re-implemented published baselines, Ahmadi (2025) [7] and Phani Kumar Kanuri (2025) [10]. Jimmy (2025) [8] is excluded from quantitative comparison for the reason given in Section 3.4.1: the source paper publishes no formula to reproduce.

All four configurations were evaluated on the same live-streamed session set (n = 1,999 paired decisions per framework, comparison run `thesis-final-20260720-exfil-v1`: 1,621 malicious, 378 benign — the same sessions submitted to every framework concurrently), scored against the same ground-truth label. There is no train/validation/test split, cross-validation fold, or repeated-trial variance estimate — a single large-sample live comparison, not a cross-validated protocol; that scope is stated as a limitation in Section 4.12 and Chapter 5. Every number in this chapter is computed by `scripts/compute_chapter4_metrics.py` and `scripts/compute_roc_data.py` from the live comparison database, not asserted.

## 4.1 Security Accuracy

| Metric | Proposed | Ablation | Ahmadi (2025) | Phani (2025) |
|---|:---:|:---:|:---:|:---:|
| TPR | **96.55%** | 68.78% | 19.68% | 10.43% |
| FPR | 2.65% | **2.65%** | 11.90% | 3.97% |
| Precision | **99.37%** | 99.11% | 87.64% | 91.85% |
| F1 | **0.979** | 0.812 | 0.321 | 0.187 |
| Accuracy | **96.70%** | 74.19% | 32.62% | 26.61% |
| AUC | **0.976** | 0.819 | 0.544 | 0.561 |

*Table 4.1 — n = 1,999 (1,621 malicious / 378 benign). Figure 4.1. 95% Wilson confidence intervals: proposed TPR [95.54, 97.33]; ablation TPR [66.49, 70.99]; ahmadi2025 TPR [17.82, 21.69]; phani2025 TPR [9.03, 12.01].*

The proposed framework leads on every accuracy dimension, with the highest AUC (0.976) of the four configurations. Ablation's AUC (0.819) — below the proposed framework's but well above both published baselines — indicates that the network-flow classifiers alone (Section 3.2.6) discriminate malicious from benign traffic substantially better than either baseline's formula, independent of the enrichment layer's own contribution (Section 4.6). Ahmadi (2025) attains the second-highest TPR (19.68%) but at a substantially higher FPR (11.90%); Phani (2025) is the most conservative baseline (TPR 10.43%, FPR 3.97%).

Precision (99.37%) and FPR (2.65%) characterise the proposed framework as a high-confidence signal: when it flags a session, it is almost always correct, and it disturbs approximately 1 in 38 legitimate sessions. Its recall is not uniform across attack categories — it is concentrated where the network-flow classifiers (Section 3.2.6) provide strong signal, examined by category in Section 4.9 — and `DENY_T = 0.75` (Section 3.5.2) is not reached by any session in this evaluation set, so the framework's deny action is not exercised here.

## 4.2 Performance

| Metric | Proposed | Ablation | Ahmadi (2025) | Phani (2025) |
|---|:---:|:---:|:---:|:---:|
| Mean latency | 798.9ms | 313.5ms | 10.8ms | 9.7ms |
| Median latency | 345.0ms | 299.0ms | 10.0ms | 9.0ms |
| p95 latency | 2,389.3ms | 400.0ms | 14.0ms | 12.0ms |
| p99 latency | 3,350.8ms | 597.1ms | 19.0ms | 18.1ms |

*Table 4.2 (n = 1,994 proposed, after the standard 5-sample warm-up exclusion). Figure 4.2.*

Median decision latency for the proposed framework is 345ms, exceeding the ≤50ms bound hypothesised in Chapter 1 (H4, Section 4.11). Ablation's median (299ms) is close behind, indicating that the four Random Forest classifier inference calls both configurations make per request — not the enrichment lookups unique to the proposed framework — account for the majority of this cost; the approximately 46ms gap between the two is attributable to the additional GeoLite2/WiGLE/JA3 lookups and cross-source distance computation the enrichment layer performs on top of the shared classifier inference. The heavy tail (p95 2.4s, p99 3.4s) is attributable to synchronous Elasticsearch writes in the decision path compounding with classifier inference cost under load. Both baselines, which apply their formula directly with no external calls or ML inference, remain two orders of magnitude faster (9–19ms across all percentiles).

## 4.3 Usability

The step-up rate over all sessions is a poor usability metric for this dataset, since the session mix is dominated by malicious sessions by construction (1,621 of 1,999). The metric that reflects what a legitimate user experiences is the step-up/deny rate restricted to genuinely benign sessions:

| Metric (benign sessions only, n = 378) | Proposed | Ablation | Ahmadi (2025) | Phani (2025) |
|---|:---:|:---:|:---:|:---:|
| Step-up rate | 2.65% | 2.65% | 7.94% | **0.00%** |
| Any friction (step-up + deny) | **2.65%** | **2.65%** | 11.90% | 3.97% |

*Table 4.3. For reference, the all-sessions step-up rate was: proposed 78.79%, ablation 56.28%, Ahmadi 9.15% (+9.05% deny, 18.21% combined), Phani 0.30% (+8.90% deny, 9.20% combined) — included for transparency, not as the headline usability number.*

Proposed and ablation impose identical friction on legitimate users (10 of the 378 benign sessions, 2.65%), a finding examined further in Section 4.6. Both configurations impose substantially less friction than Ahmadi (11.90% combined) and are close to Phani (3.97%).

## 4.4 Privacy

Privacy-preserving mechanisms — HMAC-SHA-256 hashing of contextual identifiers at ingestion, a bounded retention window — are specified as design requirements for this framework (Section 3.1). The running service code does not implement identifier hashing or an enforced deletion job, and no privacy-leakage measurement was performed. Privacy is accordingly not reported as a measured result in this chapter; it is carried into Chapter 5's hypothesis evaluation as a design requirement not yet verified.

## 4.5 Statistical Validation

McNemar's test (paired, same sessions across frameworks) compares the proposed framework's correct/incorrect calls against each other configuration on shared sessions:

| Comparison | Proposed-only correct | Other-only correct | chi-squared | p-value | Direction |
|---|:---:|:---:|:---:|:---:|---|
| Proposed vs. Ablation | 450 | 0 | 448.00 | < 10⁻⁹⁸ | **Proposed significantly better** |
| Proposed vs. Ahmadi (2025) | 1,293 | 12 | 1,255.48 | < 10⁻²⁷⁴ | **Proposed significantly better** |
| Proposed vs. Phani (2025) | 1,413 | 12 | 1,375.44 | < 10⁻³⁰⁰ | **Proposed significantly better** |

*Table 4.5.*

The proposed framework is significantly more accurate than all three other configurations. The ablation comparison is the most informative for isolating the validation layer's contribution: of the 450 sessions where the two configurations disagree, the proposed framework is correct in every one — ablation is never correct where the proposed framework is wrong — indicating that the enrichment layer's Spoofing/Tampering-specific gains (Section 4.9) are realised without any offsetting cost elsewhere in this dataset.

## 4.6 Ablation Analysis

The ablation configuration shares the same four trained network-flow classifiers as the proposed framework (Section 3.2.7): TPR 68.78%, precision 99.11%, F1 0.812.

Proposed and ablation achieve identical TPR on Denial of Service (100% both), Elevation of Privilege (82.72% both), Repudiation (100% both), and Information Disclosure (100% both, subject to the synthetic-scenario scope noted in Section 3.2.6 and Section 4.9) — categories detected entirely by the shared classifiers and boolean flags, where the enrichment layer contributes nothing beyond what ablation already achieves. The two configurations' benign-session false positives are also identical: the same 10 of 378 benign sessions are flagged by both (Section 4.3), indicating these false positives originate in the shared classifiers rather than in the enrichment layer.

Spoofing (100% vs. 31.83%) and Tampering (100% vs. 2.86%) are the two categories requiring the GPS/Wi-Fi/IP cross-source consistency check and the JA3 critical-tag lookup respectively, both structurally unavailable to ablation (Section 3.2.7). This is the validation layer's measured contribution in the current pipeline: a 68.17-percentage-point TPR gain on Spoofing and a 97.14-percentage-point gain on Tampering, with no measurable effect elsewhere. Because ablation retains the network-flow classifiers, this comparison isolates the enrichment layer's specific contribution rather than crediting it with detection capability the two configurations share equally.

## 4.7 SIEM Integration Impact

No experiment in this codebase runs the framework with SIEM feedback disabled and re-measures TPR, so no marginal-contribution figure is reported for SIEM specifically. SIEM's verified role in this evaluation is correlating and classifying live STRIDE alerts, reported in Section 4.8.

## 4.8 STRIDE Alert Distribution (Proposed Framework's Live SIEM Correlation)

| STRIDE Category | Alert Count | Severity (low / medium) |
|---|:---:|:---:|
| Denial of Service | 503 | 503 / 0 |
| Tampering | 415 | 415 / 0 |
| Information Disclosure | 242 | 83 / 159 |
| Spoofing | 216 | 216 / 0 |
| Elevation of Privilege | 181 | 179 / 2 |
| Repudiation | 156 | 155 / 1 |

*Table 4.4. Figure 4.4. These are every session where at least one validation-layer reason fired, regardless of whether the resulting risk score crossed the step-up threshold.*

## 4.9 Detection Rate by STRIDE Category

| STRIDE Category | Proposed | Ablation | Ahmadi (2025) | Phani (2025) |
|---|:---:|:---:|:---:|:---:|
| Spoofing (n≈311) | **100.00%** | 31.83% | 65.92% | 44.05% |
| Tampering (n≈245) | **100.00%** | 2.86% | 8.16% | 0.41% |
| Repudiation (n≈156) | **100.00%** | 100.00% | 12.18% | 3.85% |
| Information Disclosure (n≈244) | **100.00%** | 100.00% | 10.66% | 4.92% |
| Denial of Service (n≈341) | **100.00%** | 100.00% | 6.45% | 2.05% |
| Elevation of Privilege (n≈324) | 82.72% | 82.72% | 8.33% | 1.85% |

*Table 4.4b / Figure 4.5.*

The proposed framework leads on all six categories: four (Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) tied exactly with ablation since they are classifier/flag-driven (Section 4.6), and two (Spoofing, Tampering) at 100% specifically because of the enrichment layer's cross-source and JA3-lookup checks. Ahmadi (2025) and Phani (2025), both structurally limited to identity/context signals, trail on every category; Ahmadi's strongest result is on Spoofing (65.92%), reflecting its Mahalanobis-distance behavioural model's sensitivity to location anomalies.

The Information Disclosure figure requires a specific scope note. The 100% result for both proposed and ablation reflects detection of the synthetic `EXFILTRATION_INJECTED` scenario (Section 3.2.6) — a maximally-detectable construction by design — rather than a live test of the trained Infiltration classifier against real CIC-IDS2018 Infiltration/Bot traffic, which requires the simulator's `SIM_EXFIL_MODE=native` setting. The Infiltration classifier's demonstrated capability against real Infiltration traffic is given by its held-out test result (TPR 4.15%, precision 34.68%, AUC 0.660, Table 3.3), and this scope is restated in Section 4.12.

## 4.10 Network Condition Sensitivity

This section's data (`scripts/simulator/network_condition_results.json`) predates the calibration used elsewhere in this chapter and has not been recollected under it: its normal-condition TPR (61.0%) does not correspond to the aggregate TPR reported in Table 4.1 and should not be read alongside it. It is retained only to indicate the shape of the experiment (three conditions — normal, constrained, degraded — with graceful latency/TPR degradation under bandwidth constraint) and is flagged as requiring a full rerun before it can be cited as a current result (Chapter 5, Future Work).

## 4.11 Summary of Findings and Hypothesis Evaluation

| Hypothesis | Outcome | Evidence |
|---|---|---|
| H1: Multi-source validation improves accuracy vs. baselines | **Supported** | Significantly beats ablation, Ahmadi (2025), and Phani (2025) (Section 4.5). |
| H2: Quality-weighted scoring reduces FPR at comparable accuracy vs. baselines | **Supported** | FPR beats both Ahmadi (2.65% vs. 11.90%) and Phani (2.65% vs. 3.97%), while accuracy substantially exceeds both (Section 4.1). |
| H3: SIEM integration improves adaptive control under threat without raising false negatives | **Not evaluated** | No experiment isolates SIEM's marginal contribution (Section 4.7). |
| H4: Latency overhead ≤ 50ms under realistic conditions | **Not supported** | Median latency (345ms) is nearly 7× the hypothesised bound; p95/p99 (2.4s/3.4s) are far beyond it (Section 4.2), attributable to classifier inference and Elasticsearch-write cost. |
| H5: Privacy mechanisms preserve utility while reducing exposure | **Not supported** | Hashing/retention specified as requirements but not implemented in the running service; no privacy measurement exists (Section 4.4). |

*Table 4.6.* H1 and H2 are supported by a decisive statistical result (Section 4.5). H3 and H5 are unevaluated/unsupported for lack of evidence. H4 is not supported: the classifier integration that underlies H1/H2's result carries a latency cost outside the originally hypothesised bound. The validation layer's measured contribution is concentrated in Spoofing and Tampering detection (Section 4.6), where it produces a statistically significant improvement over the no-validation ablation configuration; the framework as a whole achieves the highest AUC of any configuration tested (0.976) and outperforms both published baseline reproductions on every accuracy metric.

## 4.12 Limitations

1. **Dataset scope.** CIC-IDS2018 remains the primary source for five of six STRIDE categories; the RBA dataset [39][40] strengthens Spoofing-category ground truth specifically.
2. **Single evaluation run, no variance estimate.** This is one large-sample live run per framework, not a cross-validated or repeated-trial protocol.
3. **Re-implementation fidelity.** Ahmadi's and Phani's threshold values are this study's own calibration (Section 3.4.4); Jimmy is excluded entirely.
4. **Network-condition results are stale** (Section 4.10).
5. **SIEM's marginal contribution is unmeasured** (Section 4.7).
6. **Information Disclosure detection has not been evaluated against real Infiltration traffic in this run.** The 100% figure reported in Section 4.9 reflects the synthetic `EXFILTRATION_INJECTED` scenario; the trained Infiltration classifier's held-out performance (TPR 4.15%, Table 3.3) is weak, and a live evaluation with `SIM_EXFIL_MODE=native` is required before a live-traffic Information Disclosure claim can be made.
7. **The Elevation of Privilege classifier's held-out precision is low (2.86%, Table 3.3)** despite its 82.72% live TPR — a trade-off between recall and false-alarm rate for this category that the aggregate metrics do not surface on their own, since Denial of Service and Credential Attack are numerically larger categories in this dataset.
8. **`DENY_T = 0.75` is not reached by any session in the current evaluation set** (Section 3.5.2) — the framework's strongest enforcement action is not exercised under current risk magnitudes.
9. **Median decision latency (345ms) exceeds the design target** (Section 4.2), attributable to classifier inference cost and synchronous Elasticsearch writes.
10. **The four network-flow classifiers are calibrated and evaluated on CIC-IDS2018 only** and have not been validated against an independent dataset.

---
**Citations used in this chapter:** [7] Ahmadi (2025); [8] Jimmy (2025); [10] Phani Kumar Kanuri (2025); [39]/[40] Wiefling et al. (RBA dataset, 2022). Full reference list in `References.md`.
