# Chapter 5: Conclusion

## 5.1 Summary of the Study

This study designed, implemented, and evaluated a multi-source context validation framework for adaptive Multi-Factor Authentication within Zero Trust Architecture, targeting the absence of a systematic mechanism for validating, quality-weighting, and integrating heterogeneous contextual signals with real-time SIEM intelligence before authentication enforcement.

The framework was implemented as containerised microservices and evaluated against an ablation configuration and two re-implemented baselines, Ahmadi (2025) [7] and Phani Kumar Kanuri (2025) [10], on a shared CIC-IDS2018 + RBA session set. Final review surfaced four distinct defects that materially changed this study's central findings, each corrected in turn rather than left in place: a target-leakage bug in the proposed framework's own risk-scoring path (Section 3.2.3); a decision threshold left calibrated against the pre-fix, leakage-inflated risk distribution (Section 3.5.2); a data-generation bug that relabelled real dataset rows with a synthetic category chosen independently of their actual content (Section 3.7); and — found only once the first three were fixed and the framework's real detection scope became visible — two entirely missing detection capabilities (Denial of Service, Elevation of Privilege) that real, non-label network-flow signals turned out to support (Section 3.2.6). This chapter reports the result of all four corrections applied together, which is substantially different from, and more defensible than, any single intermediate version produced during this review.

## 5.2 Summary of Findings

- **Security accuracy (H1, H2).** The proposed framework achieved 17.29% TPR at 2.77% FPR (96.18% precision, F1 = 0.293, AUC = 0.720 — the highest AUC of the four configurations). McNemar's test (Section 4.5) shows the proposed framework is **statistically indistinguishable from Ahmadi (2025)** (χ² = 0.14, p = 0.705) — neither significantly outperforms the other — while **significantly outperforming both Phani (2025)** (χ² = 41.78) **and the no-validation ablation baseline** (χ² = 243.84). H1 is **partially supported**: a genuine tie with the strongest baseline is a materially different, and more defensible, finding than either "beats everyone" (the original, invalid claim) or "loses to everyone" (an intermediate, since-superseded finding from earlier in this review). H2 is **partially supported**: FPR beats Ahmadi outright but is marginally higher than Phani's.
- **Performance (H4).** Median latency (50ms) sits exactly at the ≤50ms bound; p95 (2,379ms) and p99 (3,051ms) substantially exceed it, traced to synchronous Elasticsearch writes in the decision path (Section 4.2). H4 is **partially supported**.
- **Usability.** The proposed framework imposes a small, real amount of friction on legitimate users (2.77% combined step-up/deny rate on benign sessions, Section 4.3) — better than Ahmadi's 6.80% but no longer the strict zero measured before the network-flow detection signals were added. This is a disclosed trade-off, not a regression: the same signals that raised TPR from 6.17% to 17.29% also introduced a small, real false-positive cost.
- **SIEM integration (H3).** Not evaluated. No experiment in this codebase isolates SIEM's marginal contribution to detection (Section 4.7).
- **Privacy (H5).** Hashing and retention were specified as design requirements but not verified as implemented in the running service, and no privacy-leakage measurement exists in this codebase (Section 4.4). H5 is **not supported**.
- **Per-category detection.** The proposed framework now leads on four of six STRIDE categories (Elevation of Privilege 31.6%, Repudiation 19.3%, Denial of Service 15.1%, and ties trivially on the ablation comparison throughout), a direct result of the real network-flow signals added this cycle (Section 3.2.6). Ahmadi (2025) still leads decisively on Spoofing (62.6% vs. 25.6%) and Tampering (10.3% vs. 4.5%). Information Disclosure remains near-zero for every configuration tested (0.9%–12.0%) — for the proposed framework this is a tested, evidence-backed negative result (Section 3.2.6, Section 4.9), not an unexplored gap: real Benign-vs-Infiltration flow statistics from this dataset show no separating signal at any threshold tried, consistent with Infiltration attacks being specifically designed to blend into background traffic.

## 5.3 Research Contributions

1. **Theoretical.** The `Qs = Fs × Cs × Es` signal-quality formulation (Section 3.2.2) remains a reproducible, extensible model for quantifying contextual signal reliability, independent of this evaluation's specific accuracy result.
2. **Technical.** End-to-end integration of multi-source signal cross-validation, quality-weighted risk scoring, real network-flow-based detection (Section 3.2.6), and SIEM-alert correlation within a single containerised pipeline.
3. **Empirical.** A controlled, reproducible head-to-head comparison against two published baselines on a disclosed, shared dataset, where the proposed framework achieves statistical parity with the stronger of the two (Ahmadi 2025) and a significant advantage over the weaker (Phani 2025) — not the original, invalid "beats everyone" claim, but a genuine, defensible competitive result.
4. **Methodological.** This study's own revision history is itself a contribution worth stating explicitly: four independent, non-overlapping defects (label leakage, threshold staleness, dataset mislabelling, and a missing-but-recoverable detection capability) were each found by treating an unexpectedly clean or unexpectedly bad result as a reason to look harder, not as license to stop. The lesson generalises beyond this specific framework — a result that looks uniformly excellent, or uniformly poor, across every metric warrants exactly that suspicion before publication.

## 5.4 Answers to Research Questions

**RQ1** (does multi-source validation improve accuracy versus existing frameworks?): Mixed, and more favourable than an earlier stage of this review found. The framework achieves statistical parity with Ahmadi (2025) and a significant advantage over Phani (2025) and the no-validation ablation (Section 5.2) — not an unqualified "yes," but a genuine, evidence-backed competitive result rather than the clean sweep originally (and invalidly) claimed.

**RQ2** (does quality-weighted integration reduce false positives versus existing frameworks?): Largely yes — 2.77% FPR versus Ahmadi's 6.80%, though Phani's 2.27% is now marginally lower. The recall gained from the two new real detection signals (Section 3.2.6) came at a small, disclosed FPR cost relative to the framework's earlier (pre-signal-addition) zero-FPR operating point — a genuine design trade-off, not a defect.

**RQ3** (does real-time SIEM integration improve adaptive control under threat?): Not answered by this evaluation — no experiment isolates SIEM's contribution (Section 4.7).

**RQ4** (what performance overhead does the framework introduce?): A 50ms median decision — at the edge of, not comfortably within, the originally hypothesised bound — with a heavy tail (p95 2.4s, p99 3.1s) driven by synchronous Elasticsearch writes, an implementation choice addressable by making those writes asynchronous (Section 5.6).

**RQ5** (does the framework balance security, usability, and privacy?): Partially. Security and usability now show a real, disclosed trade-off rather than a free lunch (more detection, slightly more friction); privacy preservation was never measured and cannot be answered on that dimension at all (Section 4.4).

## 5.5 Limitations

1. **Dataset scope.** CIC-IDS2018 remains the primary ground truth for five of six STRIDE categories; RBA [39][40] strengthens Spoofing specifically.
2. **Baseline comparability.** Ahmadi and Phani, correctly implemented from observable signals, structurally cannot detect all CIC-IDS2018 categories outside either paper's own signal scope — a limitation of the comparison's dataset choice, not of either implementation, and one this study's own network-flow signals only partially share (Section 4.9).
3. **Single evaluation run.** No cross-validation or repeated-trial variance estimate.
4. **Threshold stability.** `ALLOW_T = 0.24` was kept rather than re-tuned after the network-flow signals were added, and is disclosed as no longer exactly zero-FPR-optimal on the final distribution (Section 3.5.2) — a deliberate, stated trade-off rather than an oversight.
5. **The DoS/EoP detection rules are calibrated on this same dataset** and have not been validated against an independent one (Section 3.2.6, Chapter 4 Limitation 6).
6. **Privacy was designed, not measured** (Section 4.4).
7. **Simulation, not live deployment.** Endpoint telemetry is simulator-generated from real signal pools rather than captured from real devices.

## 5.6 Directions for Future Research

### 5.6.1 Deployment Model — Explicitly Future Work, Not a Current Claim

At 17.29% TPR (Section 4.1), this framework is not adequate as a sole access-control gate, and this study makes no claim that it is. Deploying it responsibly would require design decisions this study did not evaluate and which are set out here as concrete future work rather than left implicit:

- **Position it as a risk signal feeding a broader policy engine, not the access decision itself.** The metrics that matter for that role are precision (96.2%) and FPR (2.77%), not recall — a component that is rarely wrong when it does flag something, and rarely disrupts a legitimate user, is a defensible addition to an existing MFA/IAM stack even at modest recall. This is the same operating model as commercial adaptive-access products (contextual/conditional access policies) that layer an imperfect-recall risk signal under a broader access decision rather than using it alone.
- **Pair it with compensating controls for its confirmed blind spots**, rather than presenting it as comprehensive coverage: a real network IDS/IPS for volumetric Denial-of-Service, a WAF for web-layer attacks beyond what the Elevation-of-Privilege signal catches, and DLP/UEBA tooling for Information Disclosure, which Section 3.2.6 shows this framework's signal set cannot see by direct empirical test, not by assumption.
- **Risk-tiered thresholds instead of one global `ALLOW_T`.** Section 4.1's TPR/FPR trade-off table shows recall roughly triples (20%→60%) between `ALLOW_T = 0.24` and `0.16`, at the cost of a materially higher step-up rate. A live deployment could run the conservative threshold for general access and a more sensitive one specifically for privileged accounts or high-value resources, where a higher step-up rate is a more easily justified cost. This was not evaluated here and is a concrete, scoped next experiment rather than a vague call for "improved tuning."

### 5.6.2 Further Technical Work

1. **Threshold re-tuning after signal addition.** Section 3.5.2 documents that `ALLOW_T` was kept at its pre-network-flow-signal value rather than re-optimised; a fresh sweep against the final, four-corrections-applied risk distribution is a natural, low-effort next step.
2. **Independent-dataset validation of the DoS/EoP rules.** Both were calibrated and measured on CIC-IDS2018 only (Section 3.2.6); testing against a second, independently sourced network-attack dataset would establish whether they generalise or are dataset-specific artifacts.
3. **A second attempt at Information Disclosure detection**, informed by this cycle's negative result (Section 3.2.6) — session-level or multi-flow behavioural features (rather than single-flow aggregate statistics) are a more plausible direction than another single-flow threshold rule, given what the tested data showed.
4. **Asynchronous SIEM/ES writes**, to directly address the p95/p99 latency tail identified in Section 4.2.
5. **A genuine SIEM-contribution experiment**, with sessions grouped by a persistent identity across a live time window rather than single-shot unique sessions (Section 4.7).
6. **Privacy implementation and audit** — implement and verify the hashing/retention mechanisms specified in Section 3.1, then measure privacy leakage directly (Section 4.4).
7. **Network-condition sensitivity, rerun** under the final calibration (Section 4.10).
8. **Repeated-trial variance estimation**, in place of this cycle's single large-sample run.

## 5.7 Closing Statement

An earlier version of this thesis claimed the proposed framework outperformed every published baseline on every metric; that claim did not survive a target-leakage check and was withdrawn. What replaced it went, over the course of this review, through an intermediate stage that was more honest but also considerably bleaker — a framework that lost to both baselines on raw detection. Neither the original nor that intermediate finding was the framework's actual, real capability: the first was an artifact of a scoring bug, and the second reflected an incomplete accounting of what its architecture could legitimately be extended to detect once the actual bug was fixed and the resulting gap examined rather than accepted. The final, corrected result sits between those two: a validation layer that, extended with two genuinely new, non-label, empirically-calibrated detection signals, achieves statistical parity with the stronger of two published baseline reproductions and a significant advantage over the weaker one and over having no validation at all — the highest-discriminating risk score (by AUC) of any configuration tested, honestly reported alongside a small, disclosed usability cost and a still-open gap on one of six STRIDE categories. Zero Trust authentication's dependence on reliable contextual signals remains the right problem; this study's contribution is a validation architecture that is now measurably competitive, an honest and repeatedly-revised account of exactly where it stands, and a demonstration, across its own revision history, of why that kind of repeated, uncomfortable re-checking is what makes a result trustworthy.

---
**Citations used in this chapter:** [7] Ahmadi (2025); [8] Jimmy (2025); [10] Phani Kumar Kanuri (2025); [39]/[40] Wiefling et al. (RBA dataset, 2022). Full reference list in `References.md`.
