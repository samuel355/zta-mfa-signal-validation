# Chapter 5: Conclusion

## 5.1 Summary of the Study

This study designed, implemented, and evaluated a multi-source context validation framework for adaptive Multi-Factor Authentication within Zero Trust Architecture, addressing the absence of a systematic mechanism for validating, quality-weighting, and integrating heterogeneous contextual signals with real-time SIEM intelligence before authentication enforcement.

The framework validates five contextual signal types (GPS, IP geolocation, Wi-Fi BSSID, device posture, TLS fingerprint) via a freshness/consistency/enrichment quality score (Section 3.2.2), computes a risk score from observable signals only, and extends detection to four network-flow-driven attack categories using independently trained Random Forest classifiers (Section 3.2.6). It was implemented as containerised microservices and evaluated against an ablation configuration and two re-implemented published baselines, Ahmadi (2025) [7] and Phani Kumar Kanuri (2025) [10], on a shared CIC-IDS2018 + RBA session set (n = 1,999).

## 5.2 Summary of Findings

- **Security accuracy (H1, H2).** The proposed framework achieved 96.55% TPR at 2.65% FPR (99.37% precision, F1 = 0.979, AUC = 0.976 — the highest AUC of the four configurations). McNemar's test (Section 4.5) shows the proposed framework significantly outperforms Ahmadi (2025) (χ² = 1255.48, p < 10⁻²⁷⁴), Phani (2025) (χ² = 1375.44, p < 10⁻³⁰⁰), and the no-validation ablation configuration (χ² = 448.00, p < 10⁻⁹⁸). H1 and H2 are **supported**.
- **Performance (H4).** Median latency (345ms) exceeds the ≤50ms bound hypothesised in Chapter 1; p95 (2,389ms) and p99 (3,351ms) exceed it further (Section 4.2), attributable to classifier inference cost and synchronous Elasticsearch writes in the decision path. H4 is **not supported**.
- **Usability.** The proposed framework imposes a small amount of friction on legitimate users (2.65% combined step-up/deny rate on benign sessions, Section 4.3), better than Ahmadi's 11.90%. Ablation imposes identical friction — the two configurations' false positives originate in the shared classifiers, not in the enrichment layer (Section 4.6).
- **SIEM integration (H3).** Not evaluated. No experiment in this codebase isolates SIEM's marginal contribution to detection (Section 4.7).
- **Privacy (H5).** Hashing and retention are specified as design requirements but not implemented in the running service, and no privacy-leakage measurement exists (Section 4.4). H5 is **not supported**.
- **Per-category detection.** The proposed framework leads on all six STRIDE categories (Section 4.9), four tied exactly with ablation (Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege — classifier/flag-driven) and two at 100% because of the enrichment layer (Spoofing, Tampering). The Information Disclosure figure reflects a synthetic evaluation scenario rather than a live test against real Infiltration traffic (Section 4.9, Section 4.12); the trained classifier's held-out evaluation (TPR 4.15%, AUC 0.660) indicates a genuinely weak signal on that specific category pending live-traffic evaluation.

## 5.3 Research Contributions

1. **Theoretical.** The `Qs = Fs × Cs × Es` signal-quality formulation (Section 3.2.2) is a reproducible, extensible model for quantifying contextual signal reliability, independent of this evaluation's specific accuracy result.
2. **Technical.** End-to-end integration of multi-source signal cross-validation, quality-weighted risk scoring, four independently trained network-flow classifiers with a leak-free held-out evaluation methodology (Section 3.2.6), and SIEM-alert correlation within a single containerised pipeline.
3. **Empirical.** A controlled, reproducible head-to-head comparison against two published baselines on a disclosed, shared dataset, in which the proposed framework achieves a statistically significant advantage over both (Section 4.5).
4. **Methodological.** A target-leakage-free risk-scoring discipline (Section 3.2.3), applied identically across the proposed framework and all three baseline re-implementations, combined with a leak-free train/validation/test split for the network-flow classifiers (Section 3.2.6) and a native-label-sourcing data pipeline (Section 3.7) — together constituting an evaluation methodology designed specifically to prevent the risk score, the training data, and the ground-truth label from ever contaminating one another.

## 5.4 Answers to Research Questions

**RQ1** (does multi-source validation improve accuracy versus existing frameworks?): Yes. The framework significantly outperforms both Ahmadi (2025) and Phani (2025), and the no-validation ablation configuration (Section 5.2).

**RQ2** (does quality-weighted integration reduce false positives versus existing frameworks?): Yes. 2.65% FPR versus Ahmadi's 11.90% and Phani's 3.97%.

**RQ3** (does real-time SIEM integration improve adaptive control under threat?): Not answered by this evaluation — no experiment isolates SIEM's contribution (Section 4.7).

**RQ4** (what performance overhead does the framework introduce?): A substantial one. Median decision latency (345ms) exceeds the hypothesised bound by a factor of nearly seven, with a heavy tail (p95 2.4s, p99 3.4s) driven by classifier inference cost and synchronous Elasticsearch writes.

**RQ5** (does the framework balance security, usability, and privacy?): Partially. Security is strong and usability cost is low; privacy preservation was not measured and cannot be answered on that dimension; performance is a disclosed weakness relative to the original design target.

## 5.5 Limitations

1. **Dataset scope.** CIC-IDS2018 remains the primary ground truth for five of six STRIDE categories; RBA [39][40] strengthens Spoofing specifically.
2. **Baseline comparability.** Ahmadi and Phani, correctly implemented from observable signals, structurally cannot detect CIC-IDS2018 categories outside either paper's own signal scope — a limitation of the comparison's dataset choice, not of either implementation.
3. **Single evaluation run.** No cross-validation or repeated-trial variance estimate.
4. **`DENY_T = 0.75` is not reached** in the current risk-score distribution (Section 3.5.2) — the framework's deny action is not exercised in this evaluation.
5. **The five signal-quality penalty constants have no measurable aggregate effect** in the current, classifier-integrated pipeline (Section 3.5.1) — a property of the current decision logic, in which the classifier-driven risk floor dominates most sessions' outcomes.
6. **Information Disclosure detection has not been evaluated against real Infiltration traffic.** The trained classifier's only evidence is a weak held-out result (TPR 4.15%, Table 3.3); live evaluation with `SIM_EXFIL_MODE=native` is required (Section 4.12).
7. **The Elevation of Privilege classifier trades recall for a low held-out precision (2.86%)** — a real cost not visible in the aggregate accuracy figures.
8. **Latency overhead is substantial** (Section 4.2), exceeding the original design target.
9. **Privacy was designed, not measured** (Section 4.4).
10. **Simulation, not live deployment.** Endpoint telemetry is simulator-generated from real signal pools rather than captured from real devices.

## 5.6 Directions for Future Research

### 5.6.1 Deployment Considerations

At 96.55% TPR and 2.65% FPR (Section 4.1), the framework is a strong risk signal, but its latency (Section 4.2) and its unexercised deny action (Section 3.5.2) are relevant constraints for deployment planning:

- **Latency reduction is a prerequisite for latency-sensitive authentication paths.** Section 4.2 attributes the 345ms median to classifier-inference cost compounding with synchronous Elasticsearch writes — both addressable through asynchronous writes and batched or cached inference rather than requiring architectural change.
- **`DENY_T` requires an explicit deployment decision.** With `DENY_T = 0.75` unreached (Section 3.5.2), the framework currently only ever recommends allow or step-up; a deployment must decide whether to lower `DENY_T` to make deny reachable, or treat step-up as the framework's practical ceiling within a broader policy engine.
- **Live-traffic evaluation of Information Disclosure detection should precede any capability claim for that category**, given the gap between the classifier's held-out performance (TPR 4.15%) and the synthetic-scenario result reported in Section 4.9.

### 5.6.2 Further Technical Work

1. **Latency reduction** via asynchronous Elasticsearch writes and optimised classifier inference, addressing the p95/p99 tail and median latency identified in Section 4.2.
2. **Live-traffic evaluation of the Infiltration classifier** using `SIM_EXFIL_MODE=native` (Section 3.2.6, Section 4.12).
3. **Precision improvement for the Elevation of Privilege classifier**, whose 2.86% held-out precision (Table 3.3) suggests additional features or a stricter decision threshold are needed for this category.
4. **Independent-dataset validation of all four network-flow classifiers**, currently calibrated and measured on CIC-IDS2018 only.
5. **A SIEM-contribution experiment**, with sessions grouped by a persistent identity across a live time window rather than single-shot unique sessions (Section 4.7).
6. **Privacy implementation and audit** — implement and verify the hashing/retention mechanisms specified in Section 3.1, then measure privacy leakage directly.
7. **Network-condition sensitivity, recollected** under the calibration used elsewhere in this study (Section 4.10).
8. **Repeated-trial variance estimation**, in place of this study's single large-sample run.

## 5.7 Closing Statement

This study set out to address a specific, well-documented gap in adaptive Zero Trust MFA: contextual signals are widely used to compute authentication risk, but rarely validated for freshness, consistency, or provenance before they influence that risk. The proposed framework closes that gap with a quantified signal-quality model (`Qs = Fs × Cs × Es`) and demonstrates, against a controlled and disclosed comparison with two published baselines and a no-validation ablation configuration, that this validation layer produces a measurable, statistically significant improvement in authentication accuracy — 96.55% TPR at 2.65% FPR, the highest AUC of any configuration tested, and a decisive advantage over both baseline reproductions.

That result is not unconditional. The framework's accuracy is not evenly distributed across attack categories: its strongest, enrichment-specific contribution is concentrated in Spoofing and Tampering detection, while Denial of Service, Elevation of Privilege, Credential Attack, and Information Disclosure are detected by network-flow classifiers whose own accuracy varies considerably by category, from near-perfect (Denial of Service, Credential Attack) to weak (Infiltration). The framework's decision latency exceeds its original design target by a wide margin, a direct consequence of the computational cost of the network-flow classifiers and the synchronous logging path. Its deny action is not exercised under the risk magnitudes observed in this evaluation, and its privacy-preservation design was not verified in the running implementation. These are reported as the current, measured state of the framework, not as defects awaiting future correction outside this study's scope — Chapter 5.6 sets out the specific technical work each would require.

Zero Trust authentication's dependence on reliable contextual signals is the problem this study set out to address, and the evidence in Chapter 4 supports the conclusion that systematic, quality-weighted signal validation is a measurable improvement over its absence. The framework presented here is a validated architecture for that purpose, evaluated on its own terms — including the categories and conditions under which it does not yet perform well — rather than only on the categories where it succeeds.

---
**Citations used in this chapter:** [7] Ahmadi (2025); [8] Jimmy (2025); [10] Phani Kumar Kanuri (2025); [39]/[40] Wiefling et al. (RBA dataset, 2022). Full reference list in `References.md`.
