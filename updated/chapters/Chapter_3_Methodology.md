# Chapter 3: Methodology

## 3.1 Framework Architecture Overview

The proposed framework is built on a modular, microservice-based architecture aligned with Zero Trust Architecture principles. A dedicated validation layer intercepts each authentication request, cross-verifies the accompanying contextual signals, computes a dynamic risk score, and enforces an appropriate authentication policy within a real-time operational envelope. Endpoints generate contextual telemetry that is normalized before entering the validation layer; the validated context vector is then passed to the risk-scoring engine, which incorporates SIEM feedback to compute a session risk score, and policy decisions are enforced by an authentication gateway applying MFA adaptively.

*Figure 3.1: Proposed Framework Architecture.*

## 3.2 Framework Components

### 3.2.1 Endpoint and Telemetry Collectors

For this controlled evaluation, endpoints are simulated by a Python-based session simulator (`scripts/simulator/enhanced_sim.py`) that draws real attack traffic from CIC-IDS2018 and RBA, and real signal pools from WiGLE, GeoLite2, and custom device-posture/TLS-fingerprint CSVs, rather than physical or virtual endpoint hardware. Each simulated session carries an IP address (geolocated through GeoLite2), a Wi-Fi BSSID (sourced from WiGLE, weighted toward a home-network cluster for genuine traffic and toward a foreign access point for injected Spoofing scenarios), device-posture attributes (patch status, EDR status, drawn from a curated device pool), a TLS/JA3 fingerprint, GPS coordinates, and — for sessions sourced directly from a CIC-IDS2018 row — real per-flow network telemetry (flow duration, packet rate, destination port, payload size; Section 3.2.6). The simulator submits each session to every framework under evaluation concurrently and records each framework's decision, latency, and risk score alongside the session's ground-truth label.

### 3.2.2 Contextual Signal Validation Layer

This is the core contribution of the framework: a stateless microservice (`services/validation`) responsible for verifying the freshness, consistency, and enrichment of incoming signals, then computing a per-signal quality score:

> *Qs = Fs × Cs × Es*

Where *Fs*, *Cs*, *Es* ∈ [0,1] are the freshness, consistency, and enrichment-trust scores for signal *s*. Unlike the idealized description in an earlier draft of this chapter, each term below is stated exactly as implemented, including where a term is intentionally held constant.

**Freshness (Fs).** Only `device_posture` carries a real per-record capture timestamp (an EDR/MDM last-check-in date). Its freshness decays linearly from the fleet's most recent check-in date over a configurable window (`DEVICE_FRESHNESS_WINDOW_DAYS`, 30 days by default): `Fs = max(0, 1 − age_days / window_days)`. The other four signal types (`gps`, `wifi_bssid`, `ip_geo`, `tls_fp`) are captured live within the same authentication request and have no independent staleness to model, so `Fs = 1.0` for these by construction. This is a deliberate scope decision, not an oversight: the earlier draft's claim of five independently grid-searched per-signal freshness windows (GPS, IP, Wi-Fi, TLS, each with its own optimal time constant and F1 curve) does not correspond to any mechanism in the implementation and has been removed rather than corrected, since no such grid search was ever run.

**Consistency (Cs).** For the three location-bearing signals (`gps`, `wifi_bssid`, `ip_geo`), consistency is a Haversine-distance cross-check: the pairwise distance between a signal's implied location and the others is compared against `DIST_THRESHOLD_KM` (100 km); within threshold scores 1.0, otherwise the signal is discounted by `GEO_MISMATCH_PENALTY` (0.5). For `device_posture` and `tls_fp`, consistency checks whether the declared device OS family agrees with the TLS handshake's inferred platform (only JA3 tags that imply a specific OS — `android_app`, `ios_app`, `safari_like` — can actually contradict the declared OS; all others are treated as consistent by default); a genuine mismatch is discounted by `DEVICE_TLS_MISMATCH_PENALTY` (0.4).

**Enrichment trust (Es).** `gps` is the anchor other signals are cross-checked against, so it is fixed at 1.0. `ip_geo` and `wifi_bssid` score 1.0 if an authoritative lookup (GeoLite2, WiGLE) resolves the signal and 0.0 otherwise. `device_posture` scores 1.0 if the device is found in the posture database and 0.0 otherwise. `tls_fp` scores 1.0 for an unremarkable JA3 tag, `CRIT_TLS_PENALTY` (0.2) if the tag matches a configured critical list (`tor_suspect`, `malware_family_x`, `scanner_tool`, `cloud_proxy`, `old_openssl`, `insecure_client`, `honeypot_fingerprint`), or 0.0 if no tag is found at all. This replaces an earlier, unimplemented design that scored enrichment against separate VPN/Tor-exit-node/malicious-IP/unknown-IP threat-intelligence indicators (`Ivpn`, `Itor`, `Imalicious`, `Iunknown`) — no such per-indicator IP threat-intelligence lookup exists in the codebase; the only enrichment penalty actually applied is the TLS critical-tag check above.

Per-signal weights *Wi* are then derived from quality: `Wi = Qi / Σ Qi` across the signals present in a session, and a separate `quality_confidence` value (mean raw *Qi*, discounted further by how many of the five signal types are missing via `MISSING_SIGNAL_PENALTY`, 0.3) is passed forward as the trust engine's confidence multiplier.

### 3.2.3 Risk Scoring and Policy Engine

The risk-scoring engine (`services/trust`) receives the validated context vector, per-signal weights, and STRIDE reason codes from the validation layer, and computes a session risk score as the sum of five real, independently implemented terms, each described in full below rather than as an idealized closed-form equation, since the actual implementation is a set of bespoke per-signal functions rather than a single algebraic sum:

1. **Base risk** — a small constant (`TRUST_BASE_GAIN`, 0.03), applied to every session regardless of signal content.
2. **Device-posture risk** — a bounded indicator (unpatched device, unknown device ID) scaled by that signal's own weight *Wi*.
3. **Location risk** — the same GPS/Wi-Fi Haversine distance computed during validation, normalized against three times the mismatch threshold and scaled by weight; distances beyond that bound are treated as maximally suspicious.
4. **TLS risk** — a small flat penalty for missing TLS data, or a weight-proportional nudge when validation has already discounted the signal for a critical tag or platform mismatch.
5. **STRIDE-reason risk** — a fixed per-category increment (Spoofing 0.12, DoS 0.30, Elevation of Privilege 0.25, Tampering/TLS anomaly 0.15, posture-outdated 0.08, repudiation 0.18, GPS/Wi-Fi mismatch 0.06/0.04) for each STRIDE reason code raised during validation, scaled by `quality_confidence` and capped at 0.4. The DoS and Elevation-of-Privilege weights were present in the risk-scoring code from early on but were, until the fix described in Section 3.2.6, dead weight — nothing in validation ever raised those reason codes, so they never contributed to any session's score. Section 3.2.6 describes the real signals that now feed them.
6. **SIEM risk** — `SIEM_HIGH_BUMP` (0.30) and `SIEM_MED_BUMP` (0.15) per high/medium-severity alert correlated to the session within a 15-minute window, scaled by confidence.

The final score is clamped to [0, 1]. Enforcement thresholds, empirically derived from a real ROC sweep (Section 3.5.2) rather than assumed: **allow** if *R* < 0.24 (`ALLOW_T`), **step-up MFA** if 0.24 ≤ *R* < 0.75, **deny** if *R* ≥ 0.75 (`DENY_T`).

**A methodological safeguard adopted after an internal review (target-leakage check).** An earlier implementation of the STRIDE-reason step above additionally mapped the session's ground-truth CIC-IDS2018/RBA `label` field directly into STRIDE reason codes (e.g., a `DDOS`-labelled session was unconditionally tagged `DOS`), and the risk engine separately added a second risk term computed directly from that same label. Because the identical label is also the value used downstream to grade each decision's TP/FP/TN/FN outcome, this constituted target leakage: the framework was, in part, scoring itself against an answer key it had already been given as an input. This was identified during a pre-submission review of the decision path (the three baseline reproductions in Section 3.4 were already written to reserve the label strictly for scoring, which made the asymmetry visible) and corrected by removing both label-derived paths, so that — like the three baselines — the proposed framework's risk score is now a function only of observable signals (GPS/Wi-Fi/IP geography, device posture, TLS fingerprint, SIEM alerts correlated from those same signals) and never of the ground-truth label itself. One consequence, reported honestly in Chapter 4 rather than concealed: the CIC-IDS2018 attack categories that inject no corresponding contextual anomaly in the five identity/context signals are, after this fix, no more detectable by those five signals than they are by the baselines'. Section 3.2.6 describes the real network-flow signals subsequently added for two of those categories (Denial of Service, Elevation of Privilege), and the negative result for the third (Information Disclosure).

### 3.2.4 Authentication Gateway / MFA Orchestrator

The gateway enforces policy decisions from the risk engine and generates feedback telemetry. Successful and failed MFA challenges, response latency, and decisions are logged and forwarded toward the SIEM index, closing the loop between authentication enforcement and enterprise-wide monitoring. In a production deployment the gateway would integrate with standard identity protocols (OAuth 2.0, OIDC, SAML); this evaluation exercises the decision path itself rather than a live IdP integration.

| MFA Method | Strengths | Weaknesses | Suitability in Adaptive MFA |
|:---|:---|:---|:---|
| SMS OTP | Simple, widely available | Susceptible to SIM swapping, delays in low-bandwidth regions | Baseline fallback, not for high-risk |
| Authenticator Apps (TOTP) | Resistant to SIM attacks, offline capability | Phishable, requires user management | Moderate-risk scenarios |
| Email OTP | Easy to deploy, universal | Vulnerable to email compromise, latency | Low-risk fallback only |
| Push Notifications | Convenient, real-time | Prone to MFA fatigue attacks | Limited, needs strict rate controls |
| Biometrics (fingerprint, face) | Non-transferable, user-friendly | Privacy concerns, spoofing with weak sensors | Strong for device-posture risk |
| Hardware Tokens (U2F, YubiKey) | Very high security, phishing-resistant | Costly, distribution overhead | High-risk cases, privileged accounts |
| FIDO2/WebAuthn | Phishing-resistant, passwordless | Uneven device/browser support | Ideal for location anomalies |
| Passkeys | Cross-device sync, strong usability | Platform dependence, early adoption | Promising for mainstream adaptive MFA |

*Table 3.1: MFA methods and enforcement considerations.*

### 3.2.5 SIEM and STRIDE Feedback

Gateway decisions that reach step-up or deny are mapped to a STRIDE category and indexed as an alert, which a subsequent session's SIEM aggregate query (scoped by session identifier, 15-minute window) can then contribute back into the risk score of a related session:

| Dominant Risk Reason | STRIDE Category |
|----|----|
| Location mismatch (GPS vs. Wi-Fi/IP) | Spoofing |
| Unpatched/unknown device posture | Tampering |
| Critical TLS fingerprint tag | Tampering |
| Real network-flow DoS signature (Section 3.2.6) | Denial of Service |
| Real network-flow web-attack signature (Section 3.2.6) | Elevation of Privilege |
| Repudiation flag | Repudiation |

*Table 3.2: STRIDE category mapping. Information Disclosure has no corresponding row — Section 3.2.6 documents the negative result behind that omission.*

Both the gateway and the SIEM service originally implemented this mapping as "take the first reason in the list, first category it happens to match" — a real bug, found during review, in which an incidental co-occurring reason (most often `POSTURE_OUTDATED`, since device posture is drawn independently of whatever scenario is active and can accompany any other reason) would win over a deliberate, scenario-defining one like `REPUDIATION` or `DOS` simply because it appeared earlier in the list. Concretely, a session with reasons `['POSTURE_OUTDATED', 'REPUDIATION']` was being logged to SIEM as "Tampering," discarding the genuine repudiation signal. Both copies of this logic (`services/gateway/app/main.py` and, separately, `services/siem/app/main.py` — which turned out to be the one actually populating the persisted alert table, making it the more consequential of the two) were rewritten to check a fixed priority order instead: deliberate/scenario-defining reasons (Repudiation, DoS, Elevation of Privilege, Spoofing) are checked ahead of the incidental ones (Tampering via TLS or posture), regardless of list position.

### 3.2.6 Network-Flow-Based Detection: Denial of Service and Elevation of Privilege

The STRIDE reasons above (Section 3.2.2) leave two categories — Denial of Service and Elevation of Privilege — undetectable by the five identity/context signals alone, since neither a DDoS flood nor a web-application exploit leaves any trace in GPS, Wi-Fi, device posture, or TLS fingerprint data. CIC-IDS2018 records real per-flow network statistics for every session, however (flow duration, packet/byte rates, port, payload size), and these are genuinely observable at decision time in a real deployment — unlike the ground-truth label, which is not. Two detection rules were built from this real telemetry, each calibrated by directly measuring real Benign vs. real attack-labelled flow statistics from the corresponding CIC-IDS2018 file, the same empirical standard applied to every other threshold in this chapter:

**Denial of Service.** Benign vs. DoS-labelled (`DoS attacks-GoldenEye`, `DoS attacks-Slowloris`) flows in `datasets/cic2018/02-15-2018.csv` were compared directly. These specific attacks are low-and-slow, not volumetric: median flow packet rate for DoS-labelled flows is 1.0/s against 126.7/s for benign flows, but median flow duration is roughly 300× longer (≈7s vs. ≈23ms) — the documented behaviour of Slowloris-style attacks, which deliberately hold a connection open while trickling minimal data specifically to resemble an idle connection rather than a flood. A flow is flagged (`DOS` reason) when duration exceeds 80 seconds, packet rate is below 0.15/s, and total forward packets are 3 or fewer. Measured directly against the real dataset: **FPR ≈ 1.4%, TPR ≈ 6.6%** — modest, and reported as such; the low ceiling is intrinsic to how deliberately this attack class resembles legitimate idle traffic, not a shortcoming of the threshold search.

**Elevation of Privilege.** Benign vs. web-attack-labelled (`Brute Force -Web`, `Brute Force -XSS`, `SQL Injection`) flows in `datasets/cic2018/02-22-2018.csv` were compared the same way. This signal is considerably cleaner: every real attack row in this file targets destination port 80, and attack payloads are substantially larger than typical HTTP traffic (median forward-direction payload 646 bytes vs. 45 bytes benign). A flow is flagged (`POLICY_ELEVATION` reason) when the destination port is 80, total forward payload exceeds 500 bytes, and mean forward packet length exceeds 120 bytes. Measured directly: **FPR ≈ 0.28%, TPR ≈ 53.6%** — the strongest real signal added this cycle, comparable in quality to the pre-existing Spoofing check.

**Information Disclosure — tested, and rejected.** The same methodology was applied to Benign vs. `Infilteration`-labelled flows in `datasets/cic2018/02-28-2018.csv`, looking for a payload-volume signature (on the reasoning that data exfiltration should show up as an unusually large backward-direction transfer). It does not: at every threshold tested, the attack detection rate was at or below the false-positive rate (e.g., at a 50,000-byte backward-payload threshold, benign FPR = 0.561% vs. attack TPR = 0.494% — the rule performs no better than chance). This is not a gap left for future work to fill with more effort; it is a direct, evidence-based negative result, and a plausible one given what CIC-IDS2018's Infiltration category actually represents — a quietly-established foothold, specifically designed not to look anomalous in aggregate flow statistics. No detection rule was written for this category. It is reported in Chapter 4 at 0% detection with this test cited as the reason, rather than left unexplained or patched with an arbitrary threshold chosen only to make the category non-empty.

## 3.3 Experimental Environment

### 3.3.1 Deployment

The framework is deployed as twelve Docker Compose services: `validation`, `trust`, `gateway`, `siem`, `metrics`, `indexer`, `elasticsearch`/`kibana` (logging and search), the `ablation` baseline, the three re-implemented published baselines (`ahmadi2025`, `jimmy2025`, `phani2025`), and the `simulator` itself. All services are containerized with pinned dependencies for reproducibility.

### 3.3.2 Datasets

- **CIC-IDS2018** — labelled network-attack traffic (DDoS, web attacks, brute force, infiltration, botnet), the primary source of malicious/benign ground truth and STRIDE-bucket injection targets.
- **RBA (Risk-Based Authentication) dataset** [39][40] — real production login events from a large-scale online service, used as a second, independent ground-truth source for the Spoofing/account-takeover category (Section 3.8).
- **WiGLE** — Wi-Fi BSSID/geolocation pairs, used for the Wi-Fi signal pool.
- **GeoLite2** (MaxMind) — IP geolocation resolution.
- **Custom device-posture and TLS/JA3 fingerprint CSVs** — curated pools representing patch/EDR status and TLS handshake fingerprints.

### 3.3.3 Network Simulation

Constrained-network experiments introduce controlled impairment (latency, packet loss, bandwidth limits) to approximate low-bandwidth remote-work conditions; results are reported in Section 4.10 together with an explicit note on which figures in that section are current versus pending re-collection under the corrected calibration.

## 3.4 Baseline Framework Implementations

Three published frameworks were re-implemented from their equations and textual descriptions and evaluated on the same dataset under identical conditions as the proposed framework. In every case, the source paper's ground-truth label is available to the re-implementation for scoring only — never as a term in the risk computation itself, the same discipline applied to the proposed framework after the correction described in Section 3.2.3.

### 3.4.1 Jimmy (2025) — Context-Aware MFA (CAMFA) [8]

[8] proposes a context-aware MFA system integrating device posture, login location, timing, and user behaviour. **The paper publishes no explicit mathematical formulas or numeric threshold/weight values**; this is a best-effort re-implementation from the textual description:

*R = W<sub>loc</sub>·location_risk + W<sub>dev</sub>·device_risk + W<sub>time</sub>·time_risk + W<sub>beh</sub>·behaviour_risk*

with *W<sub>loc</sub>* = 0.30, *W<sub>dev</sub>* = 0.25, *W<sub>time</sub>* = 0.20, *W<sub>beh</sub>* = 0.25, thresholds allow < 0.30, step-up < 0.60, deny ≥ 0.60. `location_risk` is Haversine distance from a reference location; `device_risk` reflects patch/EDR/compliance status; `time_risk` flags off-hours access; `behaviour_risk` uses TLS-fingerprint presence/consistency as an observable proxy for the paper's undefined "user behaviour" factor. Because no published formula exists, Jimmy (2025) is retained in the literature review as related work but **excluded from the head-to-head quantitative comparison in Chapter 4** — including it there would present a from-scratch reconstruction as if it were a faithful reproduction.

### 3.4.2 Ahmadi (2025) — AI-Driven Behavioral Analytics [7]

[7] proposes autonomous identity-based threat segmentation using Mahalanobis-distance anomaly detection over a learned behaviour profile combined with a contextual score:

*R = W₁·A + W₂·C*, W₁ = 0.6, W₂ = 0.4, deny threshold 0.7, step-up threshold 0.3 (the paper's own Equation 2; it does not publish the deny/step-up split used here, which was calibrated against this study's dataset — see the disclosure below).

*A* is the Mahalanobis distance of a six-feature vector (device risk, location risk, time risk, login frequency, resource count, session duration) from a fitted normal-behaviour profile; *C* = mean(device_risk, location_risk, time_risk). The normal-behaviour profile (`_MEAN`, `_COV`) is not published in the source paper and was empirically measured from 333 real benign sessions run through this study's own risk functions. An initial placeholder profile was found, on inspection, to be miscalibrated in a way that scored a genuinely benign session as *more* anomalous than a moderately spoofed one (0.160 vs. 0.084); the corrected profile (device_risk mean 0.271/var 0.076, location_risk mean 0.077/var 0.032, time_risk mean 0.267/var 0.057 analytically derived from the risk function's own day/night distribution) restores the correct ordering (clean session 0.233 → allow; spoofed session 1.0 → deny) and is the version evaluated in Chapter 4. `location_risk`'s benign baseline also required a simulator-side fix: the Wi-Fi access-point pool initially assigned APs near-uniformly across continents even for benign traffic, making genuine sessions almost as geographically scattered as spoofed ones; benign traffic is now weighted 85% toward a "home" AP cluster (`SIM_HOME_BSSID_PCT`).

### 3.4.3 Phani Kumar Kanuri (2025) — Zero Trust for Unified Communications [10]

[10] proposes a modular ZTA integrating Context Engines, Trust Engines, and adaptive learning, with two equations: *R<sub>t</sub> = α·L<sub>t</sub> + β·P<sub>t</sub>* (α = β = 0.5) and *H = M/n* (trust index, five health-metric checks). The paper specifies neither decision thresholds nor a mapping from (*H*, *R<sub>t</sub>*) to an enforcement action; this study's decision rule, calibrated against this dataset rather than transcribed from the source, is: allow if *H* ≥ 0.6 and *R<sub>t</sub>* < 0.5; step-up if *R<sub>t</sub>* < 0.55; deny otherwise.

**A logic bug found and fixed during implementation.** Because `device_posture` only carries two of the five real boolean checks Equation 2 requires (patched, EDR — the other three have no data source in this simulator and default to "healthy"), *H* can never fall below 0.6 in this implementation. An earlier decision rule (`elif H >= 0.4 or R_t < 0.7: step_up`) made that `H` clause unconditionally true given the floor above, which made `DENY` structurally unreachable regardless of `R_t`. The clause was removed. A follow-up ROC sweep against this dataset then showed `R_t` itself rarely exceeds ≈0.6 given the equation's component ranges, so `DENY_T` was recalibrated from an initial 0.70 (still empirically unreachable) down to 0.55, the level at which it is both reachable and holds FPR at 0 in the live sweep. `L_t`'s "login irregularity" term is implemented as GPS deviation from a reference location, the one real per-session signal available for it; the paper's bandwidth/CPU/memory load inputs have no corresponding field in this study's signal set and are not fabricated in their place.

### 3.4.4 Baseline threshold disclosure

Neither Ahmadi (2025) nor Phani Kumar Kanuri (2025) publishes numeric threshold or weight values for their respective equations (verified by reading both papers in full — `Papers/`). Ahmadi states weights were "calibrated through empirical tuning using grid search on validation datasets" without publishing the result; Phani's paper does not state threshold values at all. Every threshold reported in 3.4.2–3.4.3 above was therefore calibrated by this study against its own evaluation dataset, following each paper's own stated methodology where one is given, and is shown in Section 4.1's ROC figures to sit at a defensible point on that baseline's own measured curve rather than being chosen to make the baseline look weak.

## 3.5 Parameter Optimization and Justification

Unlike an earlier draft of this chapter, which reported grid-search results for parameters that do not exist in the implementation (VPN/Tor/malicious-IP enrichment penalties, five independent per-signal freshness windows), this section reports sensitivity results only for the five constants that are actually read by the running validation service: `MISSING_SIGNAL_PENALTY`, `GEO_MISMATCH_PENALTY`, `CRIT_TLS_PENALTY`, `DEVICE_TLS_MISMATCH_PENALTY`, and `DEVICE_FRESHNESS_WINDOW_DAYS` (`services/validation/app/main.py`), plus the decision thresholds `ALLOW_T`/`DENY_T` (`services/trust/app/decision_engine.py`).

Each constant is designed to be swept independently (other four held at their baseline value) by replaying real, previously validated session signals through validation → gateway → trust and re-measuring TPR/FPR/precision/F1 at each setting (`scripts/sensitivity_sweep_penalties.py`). **This sweep has not been re-run against the current, fully-corrected risk path** (label leakage removed, `ALLOW_T` recalibrated, network-flow DoS/EoP signals added) — the existing `scripts/sensitivity_sweep_results.json` predates all of those changes and should not be cited as current. Stated plainly rather than papered over with a partial or stale number: the specific optimal value for each of the five constants is pending a rerun, and should be treated as future work (Chapter 5) rather than reported here from outdated data.

### 3.5.1 Signal Weights and SIEM Weights

Base weights start equal across the signal types present in a session and are then renormalized by quality (`Wi = Qi / ΣQi`, Section 3.2.2) — there is no separate Dirichlet-sampling weight-optimization step in the running implementation. SIEM weights `SIEM_HIGH_BUMP` = 0.30, `SIEM_MED_BUMP` = 0.15 were verified against this study's dataset and required no correction.

### 3.5.2 Decision Thresholds — recalibrated twice, for two different reasons

`ALLOW_T` has now been empirically recalibrated on two separate occasions, each against a real ROC sweep of live risk-score data rather than assumed, and each is reported here rather than only keeping the final number, since the reasoning behind a threshold matters as much as its value:

1. **First calibration (0.25 → 0.30).** The original design's claimed "ROC analysis, AUC = 0.94, threshold = 0.25" did not hold up against real data — 0.25 produced an unusable false-positive rate (TPR = 99.3%, FPR = 47.9%). A real sweep against the (at-the-time still label-contaminated, Section 3.2.3) risk distribution found 0.30 to be a usable cut.
2. **Second calibration (0.30 → 0.24).** Removing the label-leakage term (Section 3.2.3) shrank real risk scores substantially. The still-current `ALLOW_T = 0.30` left most of the framework's real, non-leaked detection signal below threshold. A fresh sweep found `ALLOW_T = 0.24` as the zero-false-positive-rate-optimal cut on the (at-the-time) corrected distribution.

`ALLOW_T = 0.24` was kept, not re-tuned a third time, after the network-flow DoS and Elevation-of-Privilege signals were added (Section 3.2.6) — those signals shifted the risk distribution again, and 0.24 is no longer exactly zero-FPR-optimal on the final distribution (Figure 3.17, `scripts/roc_data.json`): FPR = 2.77% at this threshold, the true zero-FPR point now sits closer to 0.32 but at a much lower TPR (7.2% vs. 20.0%). Keeping 0.24 rather than moving to whichever threshold minimizes FPR is a deliberate trade-off disclosed here rather than hidden behind a single "optimal" label: it accepts a small, real false-positive rate in exchange for substantially more of the newly-added DoS/EoP signal actually crossing the decision boundary. Chapter 4 reports the resulting FPR honestly rather than re-selecting a threshold after the fact to preserve a "zero-FPR" headline.

`DENY_T` = 0.75 remains independently verified safe — no benign session in the evaluation set has ever crossed it — but is still never crossed by any malicious session either (max observed risk stays well under 0.75 even with the two new signal contributions), so the framework's `deny` action continues to go unexercised under current risk magnitudes. This is reported as an honest limitation in Chapter 4 rather than resolved here by lowering `DENY_T` to force deny decisions the risk scores do not actually support.

## 3.6 Evaluation Metrics

The framework is assessed across four dimensions:

1. **Security accuracy** — True Positive Rate, False Positive Rate, Precision, Recall, F1-Score, AUC.
2. **Performance** — decision latency (median, p95, p99).
3. **Usability** — step-up challenge rate.
4. **Privacy** — data-minimization design intent, evaluated in Chapter 4 against what the implementation actually verifies rather than what it was designed to do.

### 3.6.1 Comparative Evaluation Design

The proposed framework, the ablation configuration (proposed pipeline with the validation layer disabled), and the Ahmadi/Phani re-implementations are evaluated on the same live-streamed session set under identical conditions. Reported here as what was actually run, rather than as an unrun protocol dressed up as one: each session is submitted once to all four frameworks concurrently and scored against the same ground-truth label; there is no train/validation/test split, cross-validation fold, or repeated-trial variance estimate in the current evaluation — this is a single large-sample live comparison (Chapter 4 reports the exact *n*), and that scope is stated as a limitation in Chapter 5 rather than implied away. McNemar's test (the statistically appropriate test for paired binary classification outcomes on the same sessions) is used for significance testing in Chapter 4, in place of the paired t-test an earlier draft of this chapter specified — a t-test assumes continuous data and was never the correct test for this comparison even in principle.

Jimmy (2025) is excluded from this quantitative comparison for the reason given in 3.4.1: no published formula exists to reproduce, so a from-scratch implementation would be evaluating this study's own design choices under another paper's name, not that paper's method.

## 3.7 Data Generation Integrity: Native Label Sourcing

An earlier version of the session simulator assigned each session's STRIDE "bucket" (spoof/tls/dos/exfil/eop/rep/benign) by an independent random draw, applied to whichever CIC-IDS2018 row happened to come up next in iteration — completely decoupled from that row's own real content. For the network-attack buckets specifically (`dos`, `exfil`, `eop`), the simulator then unconditionally overwrote the row's real label with a synthetic one (e.g., forcing `label = "DDOS"` on whatever row the random draw selected). Because rows are pooled from four different attack-campaign days merged together, a row that was genuinely an SSH-Bruteforce flow (from the 02-14 file) had roughly a one-in-four chance of being relabelled `"DDOS"` purely by that random draw, with its real network-flow characteristics — which, per Section 3.2.6, look nothing like a DoS attack — left completely unchanged underneath the new label. A model trained or evaluated against this mislabelled data cannot win: a real signal-based detector would (correctly) fail to recognise a relabelled Bruteforce flow as anything unusual, which would then be scored as a false negative against a label that was never true in the first place.

The principle applied to fix this is direct: **the dataset's own label is ground truth and is never altered.** A CIC-IDS2018 row's real label is what the dataset's creators verified from their own attack-execution logs; this study has no basis to overwrite it, and doing so — as the earlier version did — amounts to fabricating a different, unverified dataset while presenting it as CIC-IDS2018. The simulator was rewritten around four native pools, each built by classifying rows *at load time* by their own real label (`dos_native`, `eop_native`, `exfil_native`, `credential_native` — corresponding to this dataset's real DoS, web-attack, infiltration, and brute-force categories respectively) plus a genuine Benign pool. When a network-attack bucket is selected for a session, a row is drawn from the matching native pool and passed through **completely unmodified** — its label, and the real flow telemetry behind it (Section 3.2.6), stay exactly as the dataset recorded them. Only the three categories CIC-IDS2018 has no native representation for at all — Spoofing (a GPS/Wi-Fi geographic mismatch), Tampering (a malicious TLS fingerprint), and Repudiation (an explicit denial-of-action flag) — are still synthetically constructed, and only ever on top of a row drawn from the genuine Benign pool specifically, never by overwriting an already-labelled attack row. This is a different situation from the network-attack buckets: CIC-IDS2018 is a network-traffic dataset and has no field that could represent "this GPS doesn't match this Wi-Fi AP," so constructing that scenario — deliberately, on a clean base, with the constructed label matching exactly what was built — is the only way to obtain ground truth for it at all, and is not the same act as relabelling a real attack as a different real attack.

## 3.8 RBA Dataset Addition for Spoofing Ground Truth

CIC-IDS2018's attack taxonomy is network/protocol-layer (DDoS, web attacks, infiltration) and this framework's synthetic Spoofing injection (a fixed GPS offset from a known Wi-Fi AP) is fully synthetic; neither is strong ground truth for the Spoofing category specifically. The RBA dataset [39][40] — real production login data from a large-scale SSO service, with genuine `Is Attack IP` / `Is Account Takeover` labels — was added as a supplementary source for this category, mixed 50/50 with the existing synthetic method. RBA redacts geolocation to country level in its public release, so GPS is approximated via a country centroid with small jitter, and a "home"-cluster Wi-Fi AP is attached alongside the RBA-derived (foreign) GPS so the framework's GPS-vs-Wi-Fi mismatch check has a genuine cross-source disagreement to detect — without this, RBA-sourced sessions would be undetectable by construction. The RBA dataset's own documentation states its released values are "plausible, but... totally artificial," synthesized from real production data for privacy reasons; this is disclosed on the same terms CIC-IDS2018's own synthetic-traffic limitations are disclosed in Section 2.6, not presented as raw production traffic.

---
**Citations used in this chapter:** [7] Ahmadi (2025); [8] Jimmy (2025); [10] Phani Kumar Kanuri (2025); [39]/[40] Wiefling et al. (RBA dataset, 2022). Full reference list in `References.md`.
