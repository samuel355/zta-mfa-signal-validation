# Chapter 3 — Methodology: Corrected Values and Additions

Reference material for rewriting Chapter 3 of the thesis. Everything here is
empirically derived from live simulation data or verified directly against
the source papers — nothing is guessed or carried over from the original
(partially fabricated) draft. See `updated/reference_material/chapter5_discussion_limitations.md`
for the honesty/limitations framing these numbers should carry in the final text.

## 3.2.3 / 3.5.6 — Decision thresholds (replace "ROC analysis... AUC = 0.94" claim)

The original text claimed: *"Thresholds are then applied... allow if R < 0.25,
step-up MFA if 0.25 ≤ R < 0.75, and deny or revoke if R ≥ 0.75"* and that this
came from *"ROC analysis (AUC = 0.94)"*. That analysis was never actually run —
running it for real against live risk-score data showed 0.25 produced an
unusable false-positive rate (TPR=99.3%, FPR=47.9%).

**Corrected values (empirically derived, real ROC sweep, see Figure 3.17):**

```
ALLOW_T = 0.30   (allow if R < 0.30)
DENY_T  = 0.75   (deny if R ≥ 0.75; step-up in between)
```

AUC = 0.968 (n=1,953 malicious / 105 benign sessions, live CIC-IDS2018 + RBA
simulation). Real ROC and F1-vs-threshold curves: **Figure 3.16, Figure 3.17**.

## 3.5.5 — SIEM weights (unchanged, confirmed correct)

`SIEM_HIGH_BUMP = 0.30`, `SIEM_MED_BUMP = 0.15` — these matched the thesis's
original claim and did not need correction.

## 3.4 — Baseline threshold disclosure (new — was previously absent)

Neither Ahmadi (2025) nor Phani Kumar Kanuri (2025) publishes numeric
threshold or weight values in their papers (verified by reading both PDFs in
full — see `Papers/`). Ahmadi's paper states weights were "calibrated through
... empirical tuning using grid search on validation datasets" without
publishing the result. Phani's paper never states threshold values at all.

Add this disclosure explicitly wherever the baseline equations are
introduced (3.4.1 Jimmy, 3.4.2 Ahmadi, 3.4.3 Phani):

> "The source paper does not publish numeric threshold/weight values for this
> equation. The values used in this reproduction were calibrated empirically
> against the same evaluation dataset, following the paper's own stated
> methodology (grid search / empirical tuning), and are shown to sit at a
> defensible point on that baseline's own measured ROC curve — see Figures
> 3.18–3.19 (Ahmadi) and 3.20–3.21 (Phani)."

**Ahmadi (2025) — thresholds used:** `STEPUP_T = 0.30`, `DENY_T = 0.70`
(from Eq. 2: `R = w1·A + w2·C`, `w1 = 0.6`, `w2 = 0.4`).

**Phani (2025) — thresholds used:** `H ≥ 0.6 AND R_t < 0.5 → ALLOW`;
`R_t < 0.55 → step-up`; otherwise `DENY` (`DENY_T` recalibrated down from an
initial guess of 0.70 to 0.55 — see note below).

### Note on a real logic bug found and fixed in Phani's decision rule

The first-pass transcription used `elif H >= 0.4 or R_t < 0.7: step_up else: deny`.
Because the device_posture signal only ever carries 2 real boolean checks
(patched, edr — the paper's other 3 of 5 trust-index checks have no real data
source and always default to "healthy"), `H` can never fall below 0.6 in this
implementation, making `H >= 0.4` unconditionally true and `DENY`
structurally unreachable regardless of `R_t`. Fixed by removing that clause.
A follow-up empirical ROC sweep then showed `R_t` itself rarely exceeds ~0.6
given the equation's component ranges, so `DENY_T` was lowered from an
initial 0.70 (still unreachable) to 0.55 (empirically reachable, FPR=0 at
that threshold in the live sweep).

## 3.6 (new subsection) — Ahmadi's Mahalanobis anomaly profile: empirical recalibration

Ahmadi's Eq. 2 anomaly term `A` uses a Mahalanobis distance from a "normal
behaviour profile" (`_MEAN`, `_COV`). The paper does not publish this
profile's values. The original placeholder guess
(`_MEAN = [0.10, 0.15, 0.20, ...]`) was miscalibrated badly enough that a
genuinely benign session scored *further* from "normal" than a moderately
spoofed one (anomaly score 0.160 clean vs 0.084 spoofed — backwards).

**Corrected, empirically measured profile** (from 333 real benign sessions,
run through the service's own risk functions):

```
device_risk:   mean = 0.2709   var = 0.0761
location_risk: mean = 0.0771   var = 0.0316
time_risk:     mean = 0.2667   var = 0.0572   (analytically derived — see below)
```

Two things worth stating explicitly if this level of detail goes into the
thesis:

1. **location_risk required a second pass.** The first empirical measurement
   (before a related WiFi-sampling fix, see below) gave mean=0.383 — the
   simulator's WiFi pool assigns access points essentially at random from a
   set spanning multiple continents, so *benign* sessions were nearly as
   geographically scattered as spoofed ones. Fixed by weighting normal
   traffic 85% toward a "home" AP cluster (`SIM_HOME_BSSID_PCT = 0.85`),
   after which location_risk's benign baseline dropped to the value above —
   a real, substantive fix, not just a recalibration.
2. **time_risk's raw single-run sample (mean=0.10, var=0.0009) was not used**
   — a calibration script run at one point in the day only samples one
   side of the risk function's day/night bimodal distribution, and its
   near-zero variance would make the Mahalanobis distance pathologically
   oversensitive to time-of-day. Used an analytically derived value instead
   (population mean/variance from the function's own day/night uniform
   distributions, weighted by their 16h/8h split), which is honest and
   reproducible without needing 24 hours of continuous calibration data.

Post-recalibration probe test: clean session anomaly score 0.233 → allow;
genuinely spoofed session anomaly score 1.0 → deny. Direction is now correct.

## 3.7 (new subsection) — RBA dataset addition for Spoofing ground truth

Both CIC-IDS2018's attack taxonomy (network/protocol-layer attacks: DDoS,
web attacks, infiltration) and this thesis's Spoofing-bucket injection
(synthetic GPS offset from a known WiFi AP) are, respectively, either poor
matches for context-based detection or fully synthetic. To strengthen the
Spoofing category specifically with *real* ground truth, the RBA (Risk-Based
Authentication) dataset — Wiefling et al., real production login data from a
large-scale SSO service — was added as a supplementary source (50/50 mix
with the existing synthetic method; `SIM_RBA_SPOOF_PCT = 0.5`).

RBA's `Is Attack IP` / `Is Account Takeover` fields are genuine, real-world
credential-stuffing/account-takeover ground truth (not synthetic). Full
citation and dataset-currency justification: see
`updated/reference_material/citations_rba_dataset.md`.

**Implementation note:** RBA only redacts geolocation to Country-level
granularity (Region/City are `-` in the public release), so GPS is
approximated via a country centroid (`scripts/simulator/country_centroids.py`,
249 countries) with small random jitter. A "home"-cluster WiFi AP is
attached alongside the RBA-derived (foreign) GPS specifically so the
framework's GPS-vs-WiFi mismatch check has something to compare against —
without this, RBA-sourced sessions would be undetectable by construction,
which was caught and fixed during integration testing.

**Effect on baseline Spoofing-category detection** (see Figure 4.5): mixing
in real RBA ground truth raised Ahmadi's Spoofing TPR from 62.5% to 72.3%
and Phani's from 11.2% to 24.0% — RBA's genuine cross-country relocations
produce a larger, more detectable anomaly than the synthetic 600km offset
method, which is itself informative (real account-takeover tends to look
"more anomalous" than a modest simulated GPS mismatch).

## Figures produced/regenerated this cycle

| Figure | Content |
|---|---|
| 3.16 | F1-score vs risk threshold — proposed framework |
| 3.17 | ROC curve — proposed framework (AUC = 0.968) |
| 3.18 | F1-score vs risk threshold — Ahmadi (2025) |
| 3.19 | ROC curve — Ahmadi (2025) (AUC = 0.572) |
| 3.20 | F1-score vs risk threshold — Phani (2025) |
| 3.21 | ROC curve — Phani (2025) (AUC = 0.582) |

All in `updated/figures/`. Figures 3.1–3.15 (architecture diagrams, signal
freshness/penalty optimization plots, SIEM weight optimization) predate this
investigation cycle and were **not** independently re-verified or
regenerated as part of this work — their likely source (`research_analysis/`,
`analysis_data/`) is being deleted from the repo in this same commit as
part of an earlier-session cleanup decision. If any of Figures 3.1–3.15 are
still needed for the final document, verify them against real data before
reuse rather than assuming they carry the same evidentiary standard as
3.16–3.21.
