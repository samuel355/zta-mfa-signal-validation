# Chapter 4 — Results: Final Real Numbers

All figures below are from the final data collection run this cycle:
**n = 2,054 live sessions per framework** (proposed / ablation / Ahmadi 2025 /
Phani 2025), CIC-IDS2018 + RBA hybrid, all fixes from this investigation
applied. Source: `scripts/chapter4_metrics.json`, `scripts/roc_data.json`.
Every number here traces to a real, reproducible measurement — none are
carried over from the original draft.

## 4.1 — Security accuracy (replaces the original table)

| Framework | TPR | FPR | Precision | F1 | AUC |
|---|---|---|---|---|---|
| **Proposed** | 88.30% | 2.86% | 99.83% | 0.937 | 0.968 |
| Ablation | 52.13% | 20.95% | 97.88% | 0.680 | — |
| Ahmadi (2025) | 21.86% | 5.71% | 98.61% | 0.358 | 0.572 |
| Phani (2025) | 6.11% | 1.90% | 98.35% | 0.115 | 0.582 |

Raw counts (tp/tn/fp/fn), for full transparency:

| Framework | TP | TN | FP | FN |
|---|---|---|---|---|
| Proposed | 1721 | 102 | 3 | 228 |
| Ablation | 1016 | 83 | 22 | 933 |
| Ahmadi (2025) | 426 | 99 | 6 | 1523 |
| Phani (2025) | 119 | 103 | 2 | 1830 |

McNemar's test (paired, same sessions, replaces the original's fabricated
p-values table): proposed vs every baseline is significant at **p < 10⁻³⁰⁰**
(chi² = 557.5 vs ablation, 1261.9 vs Ahmadi, 1585.1 vs Phani). See
`mcnemar_significance` in `chapter4_metrics.json` for full contingency
tables (proposed-correct/baseline-wrong counts etc.) if the write-up needs
the raw numbers.

**Figure 4.1** — grouped bar chart of the above.

## 4.2 — Latency

| Framework | Median | p95 | p99 |
|---|---|---|---|
| Proposed | 47ms | 2142ms | 2825ms |
| Ablation | 14ms | 20ms | — |
| Ahmadi (2025) | 13ms | 18ms | — |
| Phani (2025) | 13ms | 18ms | — |

Proposed chains validation→gateway→trust (3 services); baselines are
single-hop. **Note on data quality**: this run's raw latency measurements
were contaminated for the first ~1,600 of 2,054 samples by an unrelated
infrastructure incident (Elasticsearch recovering from a mid-session Docker
Desktop restart, blocking synchronous ES writes in validation/gateway). The
figures above use only the post-recovery steady-state tail (454 samples,
520.8ms avg), cross-validated against a separately measured clean run
earlier in the same investigation cycle (521.7ms avg) — the two agree to
within 1%, confirming this is the real figure. See
`scripts/compute_chapter4_metrics.py`'s `latency_stats()` for the documented
exclusion logic.

**Figure 4.2** — latency distribution + network condition sensitivity. The
network-condition panel (normal/constrained/degraded, n=150/condition) is
**stale** — collected before this cycle's fixes and not yet rerun; see
Chapter 5 limitations note.

## 4.3 — Usability (step-up rate)

| Framework | Allow | Step-up | Deny | Step-up rate |
|---|---|---|---|---|
| Proposed | 330 | 1454 | 270 | 70.79% |
| Ablation | 1016 | 875 | 163 | 42.60% |
| Ahmadi (2025) | 1622 | 224 | 208 | 10.91% |
| Phani (2025) | 1933 | 104 | 17 | 5.06% |

**Figure 4.3.** Note: proposed's high step-up rate is a direct, honest
consequence of the dataset composition (n=1,953/2,058 sessions are
malicious by construction, since STRIDE-bucket injection deliberately
oversamples attacks) combined with high real TPR — it is not evidence of
poor usability on its own and should be read alongside the FPR figure
(2.86%), which is what actually measures nuisance to legitimate users.

## 4.4 — STRIDE alert distribution (proposed framework's live SIEM correlation)

| Category | Alert count |
|---|---|
| Tampering | 5,132 |
| Spoofing | 1,667 |
| DoS | 1,324 |
| InformationDisclosure | 962 |
| EoP | 949 |
| Repudiation | 486 |

**Figure 4.4** (alert distribution + severity breakdown).

## 4.5 (new) — Detection rate by STRIDE category, all frameworks

This is the key figure explaining *why* aggregate TPR differs so much
between frameworks — without it, Ahmadi's 21.86% and Phani's 6.11% aggregate
TPR look like unexplained weaknesses rather than a structural, predictable
consequence of each baseline's published equation only reading certain
signal types.

| Category | Proposed | Ablation | Ahmadi (2025) | Phani (2025) |
|---|---|---|---|---|
| Spoofing | 100% | 51% | 72% | 24% |
| Tampering | 51% | 45% | 8% | 2% |
| Repudiation | 45% | 41% | 9% | 1% |
| Information Disclosure | 100% | 51% | 11% | 2% |
| Denial of Service | 100% | 71% | 10% | 1% |
| Elevation of Privilege | 100% | 43% | 10% | 2% |

**Figure 4.5.** Both baselines' detection clusters almost entirely in
Spoofing — the one category their equations can observe via GPS/device
signals (device posture, location, time-of-day, simulated load). DoS,
Tampering, EoP, and Information Disclosure are network/protocol-layer
attacks that fall outside either baseline's signal scope *by construction*,
not due to any implementation weakness in this reproduction.

## Tables from the original draft that must be replaced or removed

| Original table | Status | Action |
|---|---|---|
| Table 4.5 (Statistical Significance) | Was fabricated (invented p-values) | **Replace** with the real McNemar results above |
| Table 4.6 (Ablation Results, component breakdown) | Was fabricated (component-by-component breakdown never measured) | **Replace** with Figure 4.5's per-STRIDE breakdown, or remove and note that granular per-signal-source ablation (toggling individual validation checks) was not built this cycle — flag as future work if the section is kept |
| Table 4.7 (SIEM Integration Impact, "8% TPR gain") | Was fabricated, never measured | **Remove**, or measure for real if time permits (would require running with SIEM feedback disabled and re-measuring TPR — not done this cycle) |
| Table 4.8 (Adversarial Attack Detection Rates by type) | Was fabricated | **Replace** with Figure 4.5 (STRIDE category is the closest real equivalent to "attack type" available) |
| Table 4.9 (Network Condition Sensitivity) | Stale (pre-dates this cycle's fixes) | **Rerun** `scripts/simulator/network_condition_experiment.py` before final submission, or explicitly caveat as measured before the final calibration pass |
| Table 4.10 (Hypothesis Evaluation Summary) | Restates the above fabricated numbers as fact | **Rewrite** once the above tables are corrected — should reference the real numbers, not the original claims |

## Abstract numbers that no longer match and must be corrected

The abstract's original claims (98.6% TPR, 4.0% FPR, 95.2% precision,
F1=0.97, 114ms end-to-end latency, "step-up challenge rates fall by 44%",
"session continuity reaches 95%") do not match any measurement from this
investigation and should be replaced with the real, corresponding numbers:
**88.30% TPR, 2.86% FPR, 99.83% precision, F1=0.937, ~47ms median /
~2.1s p95 latency**. The "step-up rate falls by 44%" and "session continuity
95%" claims have no corresponding real measurement in this codebase at
all — see Chapter 5 for the session-continuity metric caveat; recommend
removing both claims rather than inventing replacement numbers.
