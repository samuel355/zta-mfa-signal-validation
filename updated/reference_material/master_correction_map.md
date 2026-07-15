# Master Correction Map — Abstract through Chapter 5

Full-document walkthrough (every paragraph containing a fabricated number,
claim, or citation was read directly from the .docx). Organized in document
order. Each entry gives the **original text** (or a close paraphrase) and
the **correction** to make. Chapters 3–5's real values are documented in
more depth in `chapter3_methodology.md`, `chapter4_results.md`, and
`chapter5_discussion_limitations.md` — this file is the section-by-section
index tying those numbers back to exact locations in the manuscript.

**Global find-and-replace first:** "CICIDS2017" → "CIC-IDS2018" (appears in
Abstract, 3.6 Datasets, 4.0 Overview, 4.1 Table 4.1 note, 4.9 Limitations —
at least 5 occurrences; the actual dataset used throughout implementation is
CIC-IDS2018, confirmed against `datasets/cic2018/`).

---

## Abstract (para 84)

**Original:** *"Experimental results show the proposed framework achieves
98.6% TPR, 4.0% FPR, 95.2% precision, and an F1-Score of 0.97... Decision
latency is 114ms end-to-end (28ms validation pipeline overhead)... Step-up
challenge rates fall by 44%, session continuity reaches 95%, and zero
privacy leakage is detected..."*

**Correction:** Replace with real measured values:

> "Experimental results show the proposed framework achieves 88.3% TPR,
> 2.86% FPR, 99.83% precision, and an F1-Score of 0.937 (AUC = 0.968),
> outperforming all baselines in security accuracy metrics. Median decision
> latency is 47ms, with p95 latency of 2.1s under the framework's full
> multi-source validation pipeline (validation→gateway→trust chain).
> [Step-up rate and session continuity claims: no corresponding measurement
> exists in the current implementation — see note below. Recommend removing
> both from the abstract rather than replacing with invented numbers.]"

**Privacy claim** ("zero privacy leakage") — not evaluated or contradicted
this cycle; leave as-is only if there is an actual privacy-leakage test
elsewhere in the codebase (not found during this investigation — verify
before keeping this claim, since everything else this specific and
unverified in the document turned out to be fabricated).

## Chapter 1 — Introduction

No fabricated experimental numbers here (background/problem/objectives/
research questions are motivational, not results-bearing) — **no rewrite
needed** beyond the CICIDS2017→CIC-IDS2018 fix if it appears here.

**H4 (para 187)**, *"The proposed framework introduces an authentication
latency overhead of no more than 50 milliseconds under realistic and
constrained network conditions"* — worth flagging precisely: real **median**
latency (47ms) supports H4, but **p95 (2.1s) and p99 (2.8s) do not** — a
meaningful fraction of sessions exceed 50ms by a wide margin. State this
honestly in the hypothesis evaluation rather than letting the median alone
imply blanket support for H4 — see Chapter 4/5 corrections below, which
currently claim a *constant* 28ms overhead (fabricated; real p95/p99 show
substantial variance, most plausibly from network calls to enrichment
services under load, not a constant algorithmic cost).

## Chapter 2 — Literature Review

No fabricated experimental numbers — literature synthesis only. Fix
CICIDS2017 reference in "Dataset and Experimental Limitations" (para 220).
No other rewrite needed.

## Chapter 3 — Methodology

Full detail in `chapter3_methodology.md`. Summary of what changed:
`ALLOW_T`/`DENY_T` (0.25/0.75 → 0.30/0.75, real ROC-derived), baseline
threshold disclosure (neither source paper publishes numeric values), the
Phani dead-DENY-branch fix, Ahmadi's Mahalanobis recalibration, and the new
RBA dataset section.

**Pseudocode section (para 356)** — *"The penalty multipliers were
determined through an iterative sensitivity analysis on a held-out
validation set to maximize the F1-score."* This claim was **not verified**
this cycle and, given every other "we ran a sensitivity analysis / ROC
analysis" claim in the original Chapter 3 turned out to be fabricated when
actually checked, it should be treated with the same suspicion. Either (a)
run a real sensitivity analysis on the penalty multipliers before keeping
this claim, or (b) soften it to describe the multipliers as heuristically
chosen (consistent with how the surrounding sentence already describes the
*base weights* as "assigned heuristically") rather than claiming an
empirical optimization procedure that wasn't actually run.

## Chapter 4 — Results and Discussion

Full real numbers in `chapter4_results.md`. This section maps every
original fabricated claim to its correction, in document order.

**4.0 Overview (para 604):** *"...following the four-step protocol
described in Section 3.7: the same dataset..., the same 60/20/20
train/validation/test split, 3-fold cross-validation, and 10 repeated runs
per configuration per 95% confidence intervals."* — **This entire
experimental protocol was not actually run.** There is no train/val/test
split, no cross-validation, no repeated-runs/confidence-interval procedure
anywhere in this codebase — the simulator runs a single live pass per
framework against streamed sessions. Either implement this protocol for
real (a substantial undertaking — would need real repeated trials with
variance reporting) or rewrite this paragraph to accurately describe what
was actually done: a single large-sample live evaluation (n=2,054/framework)
with no repeated-trial variance estimation. Recommend the latter given time
constraints — overclaiming an unrun statistical protocol is exactly the
kind of fabrication this whole investigation was about catching.

**4.1 Security Accuracy (Table 4.1, paras 611–613):**
Original: proposed 98.6%/4.0%/95.2%/F1=0.97; Ahmadi 92.3%/6.5%; Phani
94.2%/8.5%; Jimmy 84.6%/15.3%.
→ Real: proposed 88.30%/2.86%/99.83%/F1=0.937; ablation 52.13%/20.95%/
F1=0.680; Ahmadi 21.86%/5.71%/F1=0.358; Phani 6.11%/1.90%/F1=0.115. Jimmy
is excluded from the head-to-head comparison entirely (no published
formula — already correctly noted in 3.4.1, but Table 4.1 currently
includes fabricated Jimmy numbers that must be removed, not corrected,
since Jimmy was never actually re-implemented for comparison).

**4.2 Performance (Table 4.2, paras 626–628):** Original claims a constant
28ms pipeline overhead, 114ms end-to-end, Ahmadi ~92ms, Jimmy ~89ms.
→ Real: median 47ms, p95 2142ms, p99 2825ms (proposed); Ahmadi/Phani/
ablation all 13-15ms median (single-hop, no external validation calls).
The "constant 28ms overhead" framing is not supported — real latency is
highly variable (dominated by network/enrichment calls, not a fixed
algorithmic cost), which is actually a more honest and defensible story:
state that variability explicitly rather than claim a constant.

**Usability (Table 4.3, para 644):** Original: step-up 43%→24% (44%
reduction), session continuity 82%→95%.
→ Real step-up rate: 70.79% (proposed), measured directly, not as a
before/after reduction (there is no "before" baseline measurement of the
proposed framework without validation — that comparison is what the
`ablation` framework's 42.60% step-up rate approximates). Session
continuity has no corresponding measurement in this codebase at all (see
Chapter 5 note) — remove or scope as unmeasured.

**Privacy (Table 4.4, para 665):** "Zero privacy leakage... HMAC-SHA-256
hashing... 3-day retention" — not independently verified or contradicted
this cycle. If these mechanisms exist in the codebase (check
`services/validation/` for hashing/retention logic), the qualitative claim
may hold; the specific "zero privacy leakage across all evaluated sessions"
framing implies a formal leakage test that wasn't found — verify or soften.

**Statistical Validation (Table 4.5, para 672):** Original: paired t-tests,
p<0.01 vs one baseline, p<0.05 vs the other two, "large/medium effect
size."
→ Real: McNemar's test (the correct test for paired binary classification
outcomes — t-tests are for continuous data and were the wrong test even in
concept), p < 10⁻³⁰⁰ for proposed vs every baseline (ablation, Ahmadi,
Phani). Full contingency tables in `chapter4_results.md`. This is a
straightforwardly *stronger* real result than the fabricated one — no need
to soften anything here, just replace the test and numbers.

**Ablation Analysis (Table 4.6, para 678):** Original claims specific
component-by-component removal deltas (signal quality scoring removal:
98.6%→94% TPR; geographic cross-validation removal: 92.3%/11%; SIEM removal:
95.8% TPR; TLS removal: 96.5%/6%) — **none of these individual-component
ablation runs were ever executed.** Only one real ablation configuration
exists (`ablation` framework = proposed minus validation layer entirely:
TPR 52.13%, FPR 20.95%). Recommend removing Table 4.6's granular
per-component breakdown entirely and replacing with the single real
ablation comparison, or explicitly scoping granular component ablation as
future work (see `chapter5_discussion_limitations.md`).

**SIEM Integration Impact (Table 4.7, para 682):** Original: "8% higher
TPR" from SIEM integration under active threat conditions — **not
measured**; there is no experiment in this codebase that runs the
framework with SIEM feedback disabled and compares. Remove this specific
number; either measure it for real or state SIEM's contribution
qualitatively (it does correlate/classify STRIDE alerts in production, see
Figure 4.4) without an invented percentage.

**Adversarial Robustness (Table 4.8, para 690):** Original describes a
conceptual robustness argument (multi-source cross-validation resists
single-signal spoofing) without citing specific measured detection rates in
the text — the *concept* is consistent with real findings (Figure 4.5 shows
100% detection on Spoofing/DoS/EoP/InformationDisclosure, weaker on
Tampering/Repudiation at ~45-51%), but Table 4.8 itself (not extracted as
plain text — check its actual cell values directly in the .docx) likely
contains fabricated per-attack-type rates matching the same pattern as
Table 4.6. Recommend replacing Table 4.8 with Figure 4.5's real per-STRIDE
breakdown.

**Network Condition Sensitivity (Table 4.9, para 695):** Original: TPR
declines 4.5pp (98.6%→94.1%) under degraded conditions, FPR 4%→6%, latency
178ms. → **This entire section is stale** — it was measured before this
cycle's threshold/calibration fixes (see `network_condition_results.json`:
normal TPR=61.0%, not 98.6%; these numbers predate ALLOW_T's correction to
0.30 and don't reflect current framework behavior at all). Rerun
`scripts/simulator/network_condition_experiment.py` before using any number
from this section, or explicitly caveat it as pre-final-calibration.

**Summary of Findings and Hypothesis Evaluation (Table 4.10, para 700):**
Restates the above fabricated numbers as settled fact ("All five hypotheses
are supported..."). Must be rewritten once the above tables are corrected —
in particular, H4 (latency ≤ 50ms) is **not** cleanly supported once p95/p99
are considered (see Chapter 1 note above), so "all five hypotheses
supported" is not accurate as currently framed and needs a more nuanced
statement.

**Limitations (paras 703–707):** Largely reasonable as written (dataset
scope, re-implementation fidelity for Jimmy, simulation-vs-live-deployment)
— just needs the CICIDS2017 naming fix and the Jimmy-re-implementation
sentence corrected (Jimmy was never re-implemented for comparison at all,
per 3.4.1 — this limitations paragraph currently implies it was evaluated
with reduced fidelity, when in fact it was excluded entirely).

## Chapter 5 — Conclusion

Full detail in `chapter5_discussion_limitations.md` (dataset/baseline
comparison framing) — this section covers the numeric restatements specific
to the Conclusion chapter's own paragraphs.

**Framework description (para 744):** *"...a risk scoring engine computing
R = Rbase + Ranomaly + RSIEM with policy thresholds at 0.25 and 0.75"* —
the 0.25 threshold is the same fabricated value corrected in Chapter 3
(real: `ALLOW_T = 0.30`). Fix here too.

**Summary of Findings (paras 749–753):** Repeats every fabricated Chapter 4
number (98.6%/4.0%/95.2%/F1=0.97; baseline comparisons 92.3%/6.5%,
94.2%/8.5%, 84.6%/15.3%; 114ms/28ms latency; 44% step-up reduction;
82%→95% session continuity; 8% SIEM TPR gain; zero privacy leakage). Apply
the same corrections as the Chapter 4 section above — this is a verbatim
restatement, not new content, so the fix is identical throughout.

**Research Contributions (paras 757–759):** The *qualitative* contribution
claims (signal quality as a first-class variable, end-to-end multi-source
integration, first controlled baseline comparison) remain valid and don't
need numeric correction — these are architectural/conceptual claims, not
measurements.

**Answers to Research Questions (paras 762–766):** RQ1/RQ2/RQ3/RQ4 all
restate the fabricated numbers again (98.6%/4.0% vs baselines; 44% step-up
reduction with specific p-values "P < 0.01 vs Jimmy, p < 0.05 vs Ahmadi and
Phani"; 8% SIEM TPR gain; 28ms/114ms/178ms latency figures). Same
corrections as above apply verbatim. RQ5 (balancing security/usability/
privacy) is qualitative and doesn't need numeric correction.

**Limitations (paras 767–768, second occurrence):** Same CICIDS2017 fix.
Otherwise reasonable as written — could add a fifth limitation here: *"the
Ahmadi and Phani baselines, once correctly implemented from observable
signals rather than ground-truth labels, structurally cannot detect most
CIC-IDS2018 attack categories (network/protocol-layer attacks outside
either paper's signal scope) — a limitation of the comparison's dataset
choice more than of either implementation, addressed partially by the RBA
dataset addition for the Spoofing category (Chapter 3.7)."*

**Closing Statement (para 777):** Restates 98.6%/4.0%/F1=0.97 one final
time — same correction (88.3%/2.86%/F1=0.937).

---

## What did NOT need correction

For balance: Chapter 3.5.5 (SIEM weights, 0.30/0.15) was verified correct
and needed no change. The framework architecture description, STRIDE
category definitions, baseline equation transcriptions (once the label-
leakage bug was fixed), and the qualitative research contribution claims in
Chapter 5 all held up under investigation. Not everything in the original
draft was fabricated — the numeric/statistical claims specifically were the
problem, not the architectural or conceptual content.
