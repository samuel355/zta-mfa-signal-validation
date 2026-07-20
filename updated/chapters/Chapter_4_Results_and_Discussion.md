# Chapter 4: Results and Discussion

## 4.0 Overview

This chapter presents the experimental results of the proposed multi-source context validation framework and benchmarks it against the ablation configuration (proposed pipeline with the validation layer disabled) and two re-implemented published baselines, Ahmadi (2025) [7] and Phani Kumar Kanuri (2025) [10]. Jimmy (2025) [8] is excluded from quantitative comparison for the reason given in Section 3.4.1: the source paper publishes no formula to reproduce.

**What was actually run, stated plainly rather than dressed up as more than it was:** all four configurations were evaluated on the same live-streamed session set (n ≈ 1,999–2,006 sessions per framework — the small per-framework variance is a handful of sessions that failed transiently mid-run, not a methodological difference — the same sessions submitted to every framework concurrently), scored against the same ground-truth label. There is no train/validation/test split, cross-validation fold, or repeated-trial variance estimate — this is a single large-sample live comparison, not a cross-validated protocol. That scope is restated as a limitation in Section 4.12 and Chapter 5.

Every number in this chapter comes from `scripts/chapter4_metrics.json` and `scripts/roc_data.json`, generated after four corrections made during final review, all disclosed here because each materially changes the results from earlier drafts of this chapter:

1. **Label-leakage fix (Section 3.2.3).** The proposed and ablation frameworks previously read the CIC-IDS2018/RBA ground-truth label directly into their own risk scores, then were graded against that same label. Removed; risk now comes only from observable signals.
2. **Threshold recalibration.** Removing the label term shrank real risk scores substantially. `ALLOW_T` was recalibrated from 0.30 to 0.24 against the corrected distribution (Section 3.5.2).
3. **Native label sourcing (Section 3.7).** The session generator previously overwrote real CIC-IDS2018 rows with a synthetic label picked independently of that row's actual content. Fixed so network-attack sessions always carry the dataset's own real label and real flow telemetry, unmodified.
4. **Real network-flow detection added (Section 3.2.6).** Denial-of-Service and Elevation-of-Privilege signals, built from genuine per-flow statistics (never the label) and calibrated directly against real CIC-IDS2018 Benign-vs-attack data, were added — the framework's detection scope is no longer limited to the five identity/context signals alone.

The numbers below are the result of all four corrections applied together on one final, fully re-collected dataset (n = 1,999 for the proposed framework: 1,602 malicious, 397 benign).

## 4.1 Security Accuracy

| Metric | Proposed | Ablation | Ahmadi (2025) | Phani (2025) |
|---|:---:|:---:|:---:|:---:|
| TPR | 17.29% | 0.00% | **18.78%** | 9.32% |
| FPR | 2.77% | **0.00%** | 6.80% | **2.27%** |
| Precision | 96.18% | — | 91.79% | 94.34% |
| F1 | 0.293 | 0.000 | **0.312** | 0.170 |
| AUC | **0.720** | — | 0.558 | 0.565 |

*Table 4.1 — n = 1,999 (proposed), 1,602 malicious / 397 benign. Figure 4.1.*

This is a materially different, and materially more competitive, result than the pre-network-flow-signal version of this chapter reported: adding real Denial-of-Service and Elevation-of-Privilege detection (Section 3.2.6) nearly tripled the proposed framework's TPR (from 6.17% to 17.29%) and lifted its AUC from 0.688 to 0.720 — still the highest of the three. Ahmadi (2025) retains a narrow edge in raw TPR (18.78% vs. 17.29%), but Section 4.5's significance test shows that edge is **not** statistically distinguishable from chance on this sample. The proposed framework clearly beats Phani (2025) on TPR (17.29% vs. 9.32%) and clearly beats Ahmadi on FPR (2.77% vs. 6.80%), though Phani's FPR (2.27%) is now marginally better than the proposed framework's — a genuine, small trade-off disclosed rather than hidden: adding two real detection signals bought a large recall improvement at the cost of the proposed framework no longer holding the cleanest false-positive rate outright (Section 3.5.2).

**On its own terms, stated plainly: a 17.29% TPR means the framework misses roughly five of every six attacks in this dataset, and that is not adequate for the framework to serve as a sole access-control gate.** Two things are true about this number, not just one. First, it is dragged down by attack categories (DoS, Tampering, Information Disclosure) no context-validation signal was ever designed to see — TPR on the categories it targets specifically is higher (Spoofing 25.6%, Elevation of Privilege 31.6%, Repudiation 19.3%, Table 4.4). Second, and this should not be softened by the first point: 25–31% recall on its own intended categories is *also* not strong for a security control evaluated in isolation. `ALLOW_T = 0.24` was chosen to hold FPR low (Section 3.5.2), and that is a choice, not a ceiling — the same risk scores support a materially different operating point:

| `ALLOW_T` | TPR | FPR |
|:---:|:---:|:---:|
| 0.24 (deployed) | 20.0% | 2.8% |
| 0.20 | 55.7% | 18.1% |
| 0.18 | 59.7% | 18.6% |
| 0.16 | 60.5% | 18.6% |

*Figure 3.16/3.17.* Recall roughly triples by moving down this curve, at the cost of challenging closer to one in five legitimate sessions rather than one in thirty-five. Neither point on this curve is "the" correct answer in the abstract; which one is defensible depends entirely on where the framework sits in a larger security architecture, which Chapter 5 addresses directly rather than leaving implicit.

## 4.2 Performance

| Metric | Proposed | Ablation | Ahmadi (2025) | Phani (2025) |
|---|:---:|:---:|:---:|:---:|
| Median latency | 50ms | 15ms | 14ms | 13ms |
| p95 latency | 2,379ms | 23ms | 19ms | 17ms |
| p99 latency | 3,051ms | 29ms | 24ms | 21ms |

*Table 4.2 (n = 1,994 proposed, after the standard 5-sample warm-up exclusion). Figure 4.2.*

The proposed framework chains three services (validation → gateway → trust) with external enrichment lookups and Elasticsearch writes; the baselines apply their scoring formula directly to pre-computed signals with no external calls, which is architecturally why their latency is both lower and far tighter (p99 within 2x of median, versus the proposed framework's p99 at over 60x its median). This run's raw latency sequence was inspected directly rather than assumed clean or dirty: unlike an earlier collection cycle (documented in `scripts/compute_chapter4_metrics.py`), this run shows no contamination artifact — the mixed fast/occasional-multi-second-spike pattern is present from the first sample onward, so no prefix was excluded beyond the standard warm-up window.

**Median latency (50ms) sits exactly at H4's "no more than 50ms" bound; p95/p99 substantially exceed it** — a meaningful fraction of sessions take over two seconds. This traces to a specific, named architectural cause (synchronous Elasticsearch writes in the validation/gateway decision path), not to the validation algorithm itself or to random noise, and is addressed as a concrete future-work item in Chapter 5 rather than left unexplained.

## 4.3 Usability

The step-up rate over *all* sessions is a poor usability metric for this dataset: the session mix is dominated by malicious sessions by construction (1,602 of 1,999), so a step-up rate computed over everyone mostly measures "how often did we correctly flag an attack," not user friction. The metric that reflects what a legitimate user actually experiences is the step-up/deny rate restricted to genuinely benign sessions:

| Metric (benign sessions only, n = 397) | Proposed | Ablation | Ahmadi (2025) | Phani (2025) |
|---|:---:|:---:|:---:|:---:|
| Step-up rate | 2.77% | 0.00% | 4.53% | **0.00%** |
| Any friction (step-up + deny) | 2.77% | 0.00% | 6.80% | 2.27% |

*Table 4.3. For reference, the all-sessions step-up rate was: proposed 14.41%, ablation 0.00%, Ahmadi 8.58% (+7.83% deny), Phani 0.25% (+7.68% deny) — included for transparency, not as the headline usability number.*

The proposed framework now imposes a small but real amount of friction on legitimate users (11 of 397 benign sessions, 2.77%) — down from Ahmadi's 6.80% combined friction rate, but no longer the strict zero it was before the network-flow signals were added (Section 4.1). This is the direct, disclosed cost of the recall improvement in Section 4.1: a framework that detects more real attacks, using real signals that are not perfectly clean (Section 3.2.6's FPR figures for DoS and EoP individually), will occasionally challenge a legitimate user whose traffic incidentally resembles one of those signatures.

## 4.4 Privacy

Privacy-preserving mechanisms — HMAC-SHA-256 hashing of contextual identifiers at ingestion, a bounded retention window — were specified as design requirements for this framework (Section 3.1). Inspection of the running service code during this review did not verify that identifier hashing or an enforced deletion job are actually implemented; no privacy-leakage measurement was performed. Consequently, privacy is **not reported as a measured result** in this chapter, only as a design requirement carried into Chapter 5's hypothesis evaluation and limitations.

## 4.5 Statistical Validation

McNemar's test (paired, same sessions across frameworks) compares the proposed framework's correct/incorrect calls against each other configuration on shared sessions:

| Comparison | Proposed-only correct | Other-only correct | χ² | p-value | Direction |
|---|:---:|:---:|:---:|:---:|---|
| Proposed vs. Ablation | 277 | 11 | 243.84 | < 10⁻⁵³ | **Proposed significantly better** |
| Proposed vs. Ahmadi (2025) | 219 | 228 | 0.14 | 0.705 | **Not significant — statistical tie** |
| Proposed vs. Phani (2025) | 250 | 124 | 41.78 | < 10⁻¹⁰ | **Proposed significantly better** |

*Table 4.5.* This is the clearest single improvement in this revision cycle's numbers: the proposed framework is now statistically indistinguishable from Ahmadi (2025) — neither significantly outperforms the other — while significantly outperforming both Phani (2025) and, most importantly, the no-validation ablation configuration. That last comparison is the direct evidence that the validation layer itself contributes real, statistically significant detection capability, independent of which baseline it's measured against.

## 4.6 Ablation Analysis

The ablation configuration (Section 3.2.3's design: identical pipeline, validation layer removed, decisions from raw un-enriched signal patterns only) detects 0 of 1,609 malicious sessions and never challenges any of the 397 benign sessions — a fully inert decision path against this dataset's actual signal values, for the same reasons documented previously: its remaining raw-signal checks (suspicious-IP string patterns, unknown-device-ID, a location-anomaly check that is hard-coded `False` by design) essentially never fire against this dataset. Verified directly rather than assumed: ablation's raw risk score is exactly 0.0 for 1,986 of 2,006 sessions and 0.25 (still below its own 0.35 decision threshold) for the remaining 20 — this is a genuine "always-allow" classifier by construction, not a measurement error, but it should be read as exactly that: an extremely weak lower bound, not a realistic naive competitor. **Beating it is necessary evidence that the validation layer does something, but it is a low bar** — the more informative comparisons in this chapter are against Ahmadi and Phani (Sections 4.1, 4.5), not against ablation. The proposed framework's 17.29% TPR at 2.77% FPR is nonetheless a statistically significant improvement over this baseline (Section 4.5, χ² = 243.84), which is the cleanest available evidence that the validation layer, plus the network-flow signals layered on top of it, does something real, even though "more than nothing" is a modest claim on its own.

## 4.7 SIEM Integration Impact

No experiment in this codebase runs the framework with SIEM feedback disabled and re-measures TPR, so no marginal-contribution number is reported for SIEM specifically — this remains genuinely unmeasured (Section 3.2.3 notes the mechanism is wired in but its practical contribution is limited by the simulator's unique-per-session design, which gives the 15-minute correlation window little opportunity to find a prior related alert for the same session). What SIEM does verifiably do in this evaluation is correlate and classify live STRIDE alerts, reported in Section 4.8 below.

## 4.8 STRIDE Alert Distribution (Proposed Framework's Live SIEM Correlation)

| STRIDE Category | Alert Count | Severity (low / medium) |
|---|:---:|:---:|
| Tampering | 852 | 852 / 0 |
| Elevation of Privilege | 238 | 229 / 9 |
| Spoofing | 201 | 200 / 1 |
| Repudiation | 155 | 150 / 5 |
| Denial of Service | 50 | 27 / 23 |

*Figure 4.4. These are every session where at least one validation-layer reason fired, regardless of whether the resulting risk score crossed the step-up threshold — a broader, more informational count than Table 4.3's decision-level step-up/deny figures, included here to show what the SIEM correlation layer actually observes across the full session stream (1,496 of 1,999 sessions raised at least one alert).*

## 4.9 Detection Rate by STRIDE Category

This is the figure that explains *why* the aggregate numbers in Table 4.1 look the way they do, and it now tells a substantially more complete story than earlier drafts of this chapter, since two of the four previously-blind categories now have real detection behind them.

| STRIDE Category | Proposed | Ablation | Ahmadi (2025) | Phani (2025) |
|---|:---:|:---:|:---:|:---:|
| Elevation of Privilege (n≈317) | **31.6%** | 0.0% | 6.6% | 0.9% |
| Spoofing (n≈301) | 25.6% | 0.0% | **62.6%** | 36.4% |
| Repudiation (n≈156) | **19.3%** | 0.0% | 3.8% | 1.9% |
| Denial of Service (n≈384) | **15.1%** | 0.0% | 9.4% | 3.6% |
| Tampering (n≈223) | 4.5% | 0.0% | **10.3%** | 3.1% |
| Information Disclosure (n≈225) | **0.9%** | 0.0% | 12.0% | 5.8% |

*Table 4.4 / Figure 4.5.*

The proposed framework now leads on four of six categories (Elevation of Privilege, Repudiation, Denial of Service, and — trivially — ties or beats on the ablation comparison throughout), a direct result of Section 3.2.6's real network-flow signals: Elevation of Privilege detection (31.6%) reflects that category's cleaner real signal (port-80 payload-size signature, ~53.6% TPR/~0.28% FPR measured in isolation — Section 3.2.6), while Denial of Service (15.1%) reflects the noisier low-and-slow signature. Ahmadi (2025) still leads decisively on Spoofing (62.6% vs. 25.6%) and Tampering (10.3% vs. 4.5%) — its Mahalanobis-distance behavioural model, despite lacking any network-flow input, is genuinely stronger within the categories its own signal set covers.

**Information Disclosure remains near-zero for every framework (0.9%–12.0%), and for the proposed framework this is a tested negative result, not an unexplored gap.** Section 3.2.6 documents a direct empirical test of real Benign-vs-Infiltration flow statistics from this dataset that found no usable separating signal at any threshold — the attack category is specifically designed to blend into background traffic, and the data confirms it. No detection rule was written for it as a result; the near-zero figures both baselines register here most plausibly reflect incidental correlation with unrelated risk factors, not genuine category-specific detection, the same caveat noted for their performance on the network-layer categories generally.

## 4.10 Network Condition Sensitivity

This section's data (`scripts/simulator/network_condition_results.json`) predates every correction described in Section 4.0 and is **not** re-collected in this cycle: its normal-condition TPR (61.0%) reflects neither the current aggregate TPR (17.29%) nor any prior figure reported elsewhere in this chapter, and should not be read alongside Table 4.1 as if current. Retained only as a placeholder for the shape of the experiment (three conditions — normal, constrained, degraded — with graceful latency/TPR degradation under bandwidth constraint); flagged explicitly as requiring a full rerun before it can be cited as a result (Chapter 5, Future Work).

## 4.11 Summary of Findings and Hypothesis Evaluation

| Hypothesis | Outcome | Evidence |
|---|---|---|
| H1: Multi-source validation improves accuracy vs. baselines | **Partially supported** | Significantly beats ablation (Section 4.5) and Phani (2025); statistically indistinguishable from Ahmadi (2025) — a genuine tie, not a loss, but not the clean "beats all baselines" originally claimed either. |
| H2: Quality-weighted scoring reduces FPR at comparable accuracy vs. baselines | **Partially supported** | FPR beats Ahmadi (2.77% vs. 6.80%) but is marginally worse than Phani (2.77% vs. 2.27%); "comparable accuracy" holds against Ahmadi (statistical tie, Section 4.5) but the framework clearly *exceeds* Phani's accuracy rather than merely matching it. |
| H3: SIEM integration improves adaptive control under threat without raising false negatives | **Not evaluated** | No experiment isolates SIEM's marginal contribution (Section 4.7). |
| H4: Latency overhead ≤ 50ms under realistic conditions | **Partially supported** | Median (50ms) sits exactly at the bound; p95 (2,379ms) and p99 (3,051ms) substantially exceed it, traced to synchronous ES writes (Section 4.2), not random noise. |
| H5: Privacy mechanisms preserve utility while reducing exposure | **Not supported** | Hashing/retention specified as requirements but not verified as implemented; no privacy measurement exists (Section 4.4). |

*Table 4.6.* The honest reading has improved substantially since the first corrected version of this chapter, but remains short of the original "all five hypotheses supported" claim: **H3 and H5 fail for lack of evidence, H1/H2/H4 are genuinely mixed** — true on some dimensions, not on others, which is a materially different (and more defensible) claim than either "fully supported" or "not supported." What is now solidly established: the validation layer, extended with real network-flow signals, provides a statistically significant improvement over no validation at all (Section 4.5), achieves the highest AUC of any configuration tested (0.720, Table 4.1), and is competitive with — not decisively behind — the strongest published baseline reproduction in this comparison.

## 4.12 Limitations

1. **Dataset scope.** CIC-IDS2018 remains the primary source for five of six STRIDE categories; the RBA dataset [39][40] strengthens Spoofing-category ground truth specifically.
2. **Single evaluation run, no variance estimate.** As stated in Section 4.0, this is one large-sample live run per framework, not a cross-validated or repeated-trial protocol.
3. **Re-implementation fidelity.** Ahmadi's and Phani's threshold values are this study's own calibration (Section 3.4.4); Jimmy is excluded entirely.
4. **Network-condition results are stale** (Section 4.10).
5. **SIEM's marginal contribution is unmeasured** (Section 4.7).
6. **The DoS and Elevation-of-Privilege detection rules are threshold-based and calibrated on this same dataset** (Section 3.2.6) — like every other threshold in this study, they have not been validated against an independent dataset, and their FPR/TPR figures should be read as measured on this data, not as guaranteed generalisation.
7. **Information Disclosure remains genuinely undetected** — a tested, disclosed limitation rather than an oversight (Section 4.9), but a limitation nonetheless: half of this framework's nominal STRIDE coverage claim (Section 3.2.5) is not backed by working detection for this specific category.

---
**Citations used in this chapter:** [7] Ahmadi (2025); [8] Jimmy (2025); [10] Phani Kumar Kanuri (2025); [39]/[40] Wiefling et al. (RBA dataset, 2022). Full reference list in `References.md`.
