# Chapter 3: Methodology

This study follows the Design Science Research (DSR) paradigm [41][42], appropriate for research whose primary contribution is a designed artifact evaluated against defined objectives rather than an explanatory theory tested against observational data. The design cycle followed here — problem identification (Chapter 1), artifact design (this chapter), and rigorous, comparative demonstration and evaluation (Chapter 4) — follows Peffers et al.'s [42] design science research methodology process model. Hevner et al.'s [41] design-science guidelines are applied throughout: the framework is evaluated against real datasets and published-baseline reproductions rather than a self-reported result (design evaluation); the evaluation methodology, including its own leak-prevention discipline (Section 3.2.3, Section 3.7), is disclosed in full (research rigor); and results are reported inclusive of the categories and conditions under which the artifact does not yet perform well (Chapter 4, communication of results).

## 3.1 Framework Architecture Overview

The proposed framework is built on a modular, microservice-based architecture aligned with Zero Trust Architecture principles. A dedicated validation layer intercepts each authentication request, cross-verifies the accompanying contextual signals, computes a dynamic risk score, and enforces an appropriate authentication policy within a real-time operational envelope. Endpoints generate contextual telemetry that is normalized before entering the validation layer; the validated context vector is then passed to the risk-scoring engine, which incorporates SIEM feedback to compute a session risk score, and policy decisions are enforced by an authentication gateway applying MFA adaptively.

*Figure 3.1: Proposed Framework Architecture.*

## 3.2 Framework Components

### 3.2.1 Endpoint and Telemetry Collectors

For this controlled evaluation, endpoints are simulated by a Python-based session simulator (`scripts/simulator/enhanced_sim.py`) that draws real attack traffic from CIC-IDS2018 [44] and RBA, and real signal pools from WiGLE, GeoLite2, and custom device-posture/TLS-fingerprint CSVs, rather than physical or virtual endpoint hardware. Each simulated session carries an IP address (geolocated through GeoLite2), a Wi-Fi BSSID (sourced from WiGLE, weighted toward a home-network cluster for genuine traffic and toward a foreign access point for injected Spoofing scenarios), device-posture attributes (patch status, EDR status, drawn from a curated device pool), a TLS/JA3 fingerprint, GPS coordinates, and — for sessions sourced directly from a CIC-IDS2018 row — real per-flow network telemetry (flow duration, packet rate, destination port, payload size; Section 3.2.6). The simulator submits each session to every framework under evaluation concurrently and records each framework's decision, latency, and risk score alongside the session's ground-truth label.

### 3.2.2 Contextual Signal Validation Layer

This is the core contribution of the framework: a stateless microservice (`services/validation`) responsible for verifying the freshness, consistency, and enrichment of incoming signals, then computing a per-signal quality score:

> *Qs = Fs × Cs × Es*

Where *Fs*, *Cs*, *Es* ∈ [0,1] are the freshness, consistency, and enrichment-trust scores for signal *s*.

**Freshness (Fs).** Only `device_posture` carries a per-record capture timestamp (an EDR/MDM last-check-in date). Its freshness decays linearly from the fleet's most recent check-in date over a configurable window (`DEVICE_FRESHNESS_WINDOW_DAYS`, 30 days by default): `Fs = max(0, 1 − age_days / window_days)`. The other four signal types (`gps`, `wifi_bssid`, `ip_geo`, `tls_fp`) are captured live within the same authentication request and have no independent staleness to model, so `Fs = 1.0` for these by construction.

**Consistency (Cs).** For the three location-bearing signals (`gps`, `wifi_bssid`, `ip_geo`), consistency is a Haversine-distance cross-check: the pairwise distance between a signal's implied location and the others is compared against `DIST_THRESHOLD_KM` (100 km); within threshold scores 1.0, otherwise the signal is discounted by `GEO_MISMATCH_PENALTY` (0.5). For `device_posture` and `tls_fp`, consistency checks whether the declared device OS family agrees with the TLS handshake's inferred platform (only JA3 tags that imply a specific OS — `android_app`, `ios_app`, `safari_like` — can actually contradict the declared OS; all others are treated as consistent by default); a genuine mismatch is discounted by `DEVICE_TLS_MISMATCH_PENALTY` (0.4).

**Enrichment trust (Es).** `gps` is the anchor other signals are cross-checked against, so it is fixed at 1.0. `ip_geo` and `wifi_bssid` score 1.0 if an authoritative lookup (GeoLite2, WiGLE) resolves the signal and 0.0 otherwise. `device_posture` scores 1.0 if the device is found in the posture database and 0.0 otherwise. `tls_fp` scores 1.0 for an unremarkable JA3 tag, `CRIT_TLS_PENALTY` (0.2) if the tag matches a configured critical list (`tor_suspect`, `malware_family_x`, `scanner_tool`, `cloud_proxy`, `old_openssl`, `insecure_client`, `honeypot_fingerprint`), or 0.0 if no tag is found at all.

Per-signal weights *Wi* are then derived from quality: `Wi = Qi / Σ Qi` across the signals present in a session, and a separate `quality_confidence` value (mean raw *Qi*, discounted further by how many of the five signal types are missing via `MISSING_SIGNAL_PENALTY`, 0.3) is passed forward as the trust engine's confidence multiplier.

### 3.2.3 Risk Scoring and Policy Engine

The risk-scoring engine (`services/trust`) receives the validated context vector, per-signal weights, and STRIDE reason codes from the validation layer, and computes a session risk score as the sum of six terms:

1. **Base risk** — a small constant (`TRUST_BASE_GAIN`, 0.03), applied to every session regardless of signal content.
2. **Device-posture risk** — a bounded indicator (unpatched device, unknown device ID) scaled by that signal's own weight *Wi*.
3. **Location risk** — the same GPS/Wi-Fi Haversine distance computed during validation, normalized against three times the mismatch threshold and scaled by weight; distances beyond that bound are treated as maximally suspicious.
4. **TLS risk** — a small flat penalty for missing TLS data, or a weight-proportional nudge when validation has already discounted the signal for a critical tag or platform mismatch.
5. **STRIDE-reason risk** — a fixed per-category increment (Spoofing 0.12, DoS 0.30, Elevation of Privilege 0.25, Tampering/TLS anomaly 0.15, posture-outdated 0.08, repudiation 0.18, GPS/Wi-Fi mismatch 0.06/0.04) for each STRIDE reason code raised during validation, scaled by `quality_confidence` and capped at 0.4. The Denial of Service and Elevation-of-Privilege terms are driven by the trained network-flow classifiers described in Section 3.2.6.
6. **SIEM risk** — `SIEM_HIGH_BUMP` (0.30) and `SIEM_MED_BUMP` (0.15) per high/medium-severity alert correlated to the session within a 15-minute window, scaled by confidence.

The final score is clamped to [0, 1]. Enforcement thresholds, derived from ROC (Receiver Operating Characteristic) analysis of live risk-score data (Section 3.5.2): **allow** if *R* < 0.24 (`ALLOW_T`), **step-up MFA** if 0.24 ≤ *R* < 0.75, **deny** if *R* ≥ 0.75 (`DENY_T`).

The risk score is computed exclusively from observable signals — GPS/Wi-Fi/IP geography, device posture, TLS fingerprint, network-flow classifier outputs (Section 3.2.6), and SIEM alerts correlated from those same signals — and never from the ground-truth CIC-IDS2018/RBA `label` field. This separation is a deliberate constraint rather than an implementation detail: because the same label is also the value used downstream to grade each decision's TP/FP/TN/FN outcome (Section 3.6), any dependency of the risk score on it would constitute target leakage, scoring the framework in part against an answer key it had already been given as an input. The three baseline re-implementations (Section 3.4) observe the identical constraint, so all four configurations compared in Chapter 4 are evaluated on the same terms. One consequence of this constraint is that CIC-IDS2018 attack categories which inject no corresponding anomaly into the five identity/context signals are no more detectable by those five signals than they are by the baselines; Section 3.2.6 describes the network-flow signals that extend detection coverage to four such categories.

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
| Network-flow DoS signature (Section 3.2.6) | Denial of Service |
| Network-flow web-attack signature (Section 3.2.6) | Elevation of Privilege |
| Corroborated exfiltration telemetry / Infiltration classifier (Section 3.2.6) | Information Disclosure |
| Repudiation flag | Repudiation |

*Table 3.2: STRIDE category mapping.*

Because a session's device-posture and TLS-fingerprint signals are drawn independently of whichever STRIDE scenario is active, they may co-occur incidentally with any other reason code — for example, a Repudiation-scenario session whose independently-assigned device happens to be unpatched. STRIDE category assignment therefore follows a fixed priority order rather than reason-list position: deliberate, scenario-defining reasons (Repudiation, Denial of Service, Spoofing, Elevation of Privilege, Information Disclosure) are checked ahead of the two incidental Tampering reasons (critical TLS fingerprint, outdated device posture), in both the gateway (`services/gateway/app/main.py`) and the SIEM correlation service (`services/siem/app/main.py`, the service that persists the alert table used in Chapter 4).

### 3.2.6 Network-Flow-Based Detection: Denial of Service, Elevation of Privilege, Credential Attack, and Infiltration

The STRIDE reasons above (Section 3.2.2) leave four categories undetectable by the five identity/context signals alone, since none of a DDoS flood, a web-application exploit, a credential-stuffing attempt, or a quietly-established foothold leaves any trace in GPS, Wi-Fi, device posture, or TLS fingerprint data. CIC-IDS2018 [44] records real per-flow network statistics for every session, however (flow duration, packet/byte rates, port, payload size, inter-arrival-time statistics, TCP flag counts), and these are genuinely observable at decision time in a real deployment — unlike the ground-truth label, which is not.

Denial of Service, Elevation of Privilege, Credential Attack, and Infiltration are each detected by an independently trained Random Forest classifier [43] (`scripts/train_dos_eop_classifiers.py`), fit on the real per-flow feature set (73 columns) of the corresponding CIC-IDS2018 source file: Denial of Service (`02-15-2018.csv`), Elevation of Privilege (`02-22-2018.csv`), Credential Attack (`02-14-2018.csv`), and Infiltration (`02-28-2018.csv`). A Random Forest ensemble was selected over a hand-specified threshold rule for its capacity to learn nonlinear interactions across the full feature set rather than requiring manual selection of two or three discriminating features.

**Training methodology.** Each classifier uses 200 trees (maximum depth 12, minimum 5 samples per leaf, class-balanced). Identifier columns (label, timestamp, flow ID, source/destination IP, source port) are excluded from the feature set, as are five TCP-stack/OS-configuration fingerprint columns (`Init Fwd Win Byts`, `Init Bwd Win Byts`, `Fwd Seg Size Min`, `Fwd Header Len`, `Bwd Header Len`). These five were verified directly against the raw data to be near-categorical splits driven by which host generated the traffic in CIC-IDS2018's testbed rather than by attack behaviour, and are excluded on principle: a classifier trained on them would be learning to distinguish which machine produced a flow, not whether the flow constitutes an attack, and would not generalise to a real deployment.

A deterministic, hash-based train/validation/test split (60/20/20, `scripts/simulator/data_split.py`) is applied identically by the training script and the live simulator, so the live evaluation stream draws only from the held-out test partition of each split file — no row a classifier trained or was threshold-tuned on can appear in a live evaluation session. Each classifier's decision threshold is selected on the validation split by maximising true-positive rate subject to a validation false-positive rate no greater than 1%; the test split is reserved exclusively for the final evaluation reported below.

**Held-out test results** (TPR: true positive rate; FPR: false positive rate; AUC: area under the ROC curve; n = 209,624 flows for Denial of Service/Elevation of Privilege/Credential Attack, n = 122,688 for Infiltration):

| Classifier | Source file | n (test) | TPR | FPR | Precision | F1 | AUC |
|---|---|---:|---:|---:|---:|---:|---:|
| Denial of Service | `02-15-2018.csv` | 209,624 | 99.99% | 0.70% | 88.37% | 0.938 | 0.99998 |
| Elevation of Privilege | `02-22-2018.csv` | 209,624 | 84.29% | 0.96% | 2.86% | 0.055 | 0.9962 |
| Credential Attack | `02-14-2018.csv` | 209,624 | 99.999% | 0.065% | 99.89% | 0.9994 | 0.999999 |
| Infiltration | `02-28-2018.csv` | 122,688 | 4.15% | 0.98% | 34.68% | 0.074 | 0.660 |

*Table 3.3: Held-out test performance for the four trained network-flow classifiers.*

Denial of Service and Credential Attack are detected with near-perfect fidelity (TPR > 99.9%, FPR < 1%). Elevation of Privilege reaches a substantially higher recall (84.3%) at a low held-out precision (2.86%): the web-attack class is a small minority of flows even within its own source file, so the majority of the classifier's positive predictions on the held-out split are false alarms. Infiltration is the weakest of the four classifiers by a wide margin (TPR 4.15%, precision 34.68%, AUC 0.660) — only marginally better than chance at distinguishing a quietly-established foothold from background traffic, consistent with CIC-IDS2018's Infiltration category being constructed specifically not to look anomalous in aggregate flow statistics.

The live simulator constructs Information Disclosure scenarios in one of two modes, controlled by `SIM_EXFIL_MODE`: `observable`, which builds a synthetic session-level exfiltration scenario from DLP (Data Loss Prevention) alert and abnormal-outbound-volume telemetry (`dlp_alert`, `sensitive_data_accessed`, `destination_is_new` all true, outbound-volume ratio 25–80× baseline); or `native`, which draws directly from the real CIC-IDS2018 Infiltration/Bot pool. Chapter 4's evaluation run uses `observable` mode; the Infiltration classifier's demonstrated capability against real Infiltration traffic is therefore given by its held-out test result above (Table 3.3) rather than by the live evaluation figures, and this scope is stated explicitly in Chapter 4's limitations (Section 4.12).

### 3.2.7 Ablation Configuration

To isolate what the validation layer specifically contributes, an ablation configuration (`services/ablation`) processes the identical five-signal vector and the same real `network_flow` telemetry as the proposed framework, through the same four trained classifiers described above, but without validation's enrichment step: no GeoLite2/WiGLE lookups (so the GPS-versus-Wi-Fi-versus-IP Spoofing cross-check cannot be computed at all), no JA3 reference-table lookup (so the Tampering check is similarly unavailable), and per-signal quality Qi = Fi × Ci × Ei replaced by a binary presence indicator, normalised the same Wi = Qi/ΣQi way — mirroring Phani (2025)'s [10] own H = M/n trust-index structure rather than inventing a different simplification.

Because ablation shares the same trained classifiers as the proposed framework, it retains full detection capability for the four network-flow-driven categories (Denial of Service, Elevation of Privilege, Credential Attack, Information Disclosure) and for Repudiation (a boolean flag requiring no enrichment). Its measured gap to the proposed framework (Section 4.6) is therefore attributable specifically to the two categories that structurally require the enrichment layer — Spoofing and Tampering.

## 3.3 Experimental Environment

### 3.3.1 Deployment

The framework is deployed as twelve Docker Compose services: `validation`, `trust`, `gateway`, `siem`, `metrics`, `indexer`, `elasticsearch`/`kibana` (logging and search), the `ablation` baseline, the three re-implemented published baselines (`ahmadi2025`, `jimmy2025`, `phani2025`), and the `simulator` itself. All services are containerized with pinned dependencies for reproducibility.

### 3.3.2 Datasets

- **CIC-IDS2018** [44] — labelled network-attack traffic (DDoS, web attacks, brute force, infiltration, botnet), the primary source of malicious/benign ground truth and STRIDE-bucket injection targets.
- **RBA (Risk-Based Authentication) dataset** [39][40] — real production login events from a large-scale online service, used as a second, independent ground-truth source for the Spoofing/account-takeover category (Section 3.8).
- **WiGLE** — Wi-Fi BSSID/geolocation pairs, used for the Wi-Fi signal pool.
- **GeoLite2** (MaxMind) — IP geolocation resolution.
- **Custom device-posture and TLS/JA3 fingerprint CSVs** — curated pools representing patch/EDR status and TLS handshake fingerprints.

### 3.3.3 Network Simulation

Constrained-network experiments introduce controlled impairment (latency, packet loss, bandwidth limits) to approximate low-bandwidth remote-work conditions; results are reported in Section 4.10, which also notes the currency status of that specific figure set relative to the calibration used elsewhere in this chapter.

## 3.4 Baseline Framework Implementations

Three published frameworks were re-implemented from their equations and textual descriptions and evaluated on the same dataset under identical conditions as the proposed framework. In every case, the source paper's ground-truth label is available to the re-implementation for scoring only — never as a term in the risk computation itself, the same constraint applied to the proposed framework (Section 3.2.3).

### 3.4.1 Jimmy (2025) — Context-Aware MFA (CAMFA) [8]

[8] proposes a context-aware MFA system integrating device posture, login location, timing, and user behaviour. **The paper publishes no explicit mathematical formulas or numeric threshold/weight values**; this is a best-effort re-implementation from the textual description:

*R = W<sub>loc</sub>·location_risk + W<sub>dev</sub>·device_risk + W<sub>time</sub>·time_risk + W<sub>beh</sub>·behaviour_risk*

with *W<sub>loc</sub>* = 0.30, *W<sub>dev</sub>* = 0.25, *W<sub>time</sub>* = 0.20, *W<sub>beh</sub>* = 0.25, thresholds allow < 0.30, step-up < 0.60, deny ≥ 0.60. `location_risk` is Haversine distance from a reference location; `device_risk` reflects patch/EDR/compliance status; `time_risk` flags off-hours access; `behaviour_risk` uses TLS-fingerprint presence/consistency as an observable proxy for the paper's undefined "user behaviour" factor. Because no published formula exists, Jimmy (2025) is retained in the literature review as related work but **excluded from the head-to-head quantitative comparison in Chapter 4** — including it there would present a from-scratch reconstruction as if it were a faithful reproduction.

### 3.4.2 Ahmadi (2025) — AI-Driven Behavioral Analytics [7]

[7] proposes autonomous identity-based threat segmentation using Mahalanobis-distance anomaly detection over a learned behaviour profile combined with a contextual score:

*R = W₁·A + W₂·C*, W₁ = 0.6, W₂ = 0.4, deny threshold 0.7, step-up threshold 0.3 (the paper's own Equation 2; the deny/step-up split is not published and was calibrated against this study's dataset — Section 3.4.4).

*A* is the Mahalanobis distance of a six-feature vector (device risk, location risk, time risk, login frequency, resource count, session duration) from a fitted normal-behaviour profile; *C* = mean(device_risk, location_risk, time_risk). The normal-behaviour profile (`_MEAN`, `_COV`) is not published in the source paper; it was empirically fitted from 333 real benign sessions run through this study's own risk functions, with device_risk (mean 0.271, variance 0.076), location_risk (mean 0.077, variance 0.032), and time_risk (mean 0.267, variance 0.057) derived analytically from the risk functions' own distribution. Benign Wi-Fi traffic is weighted 85% toward a "home" access-point cluster (`SIM_HOME_BSSID_PCT`), reflecting the geographic concentration expected of genuine user behaviour rather than a uniform global distribution.

### 3.4.3 Phani Kumar Kanuri (2025) — Zero Trust for Unified Communications [10]

[10] proposes a modular ZTA integrating Context Engines, Trust Engines, and adaptive learning, with two equations: *R<sub>t</sub> = α·L<sub>t</sub> + β·P<sub>t</sub>* (α = β = 0.5) and *H = M/n* (trust index, five health-metric checks). The paper specifies neither decision thresholds nor a mapping from (*H*, *R<sub>t</sub>*) to an enforcement action; this study's decision rule, calibrated against this dataset, is: allow if *H* ≥ 0.6 and *R<sub>t</sub>* < 0.5; step-up if *R<sub>t</sub>* < 0.55; deny otherwise.

`device_posture` supplies two of Equation 2's five health checks (patched, EDR); the remaining three have no corresponding field in this study's signal set and default to "healthy" rather than being fabricated. Consequently *H* cannot fall below 0.6 in this implementation, and the deny decision is governed by *R<sub>t</sub>* alone. `DENY_T` was calibrated via ROC sweep against this dataset to 0.55, the threshold at which deny is both reachable given *R<sub>t</sub>*'s empirical range and holds FPR at 0. `L<sub>t</sub>`'s "login irregularity" term is implemented as GPS deviation from a reference location, the one real per-session signal available for it; the paper's bandwidth/CPU/memory load inputs have no corresponding field in this study's signal set and are not fabricated in their place.

### 3.4.4 Baseline threshold disclosure

Neither Ahmadi (2025) nor Phani Kumar Kanuri (2025) publishes numeric threshold or weight values for their respective equations (verified by reading both papers in full — `Papers/`). Ahmadi states weights were "calibrated through empirical tuning using grid search on validation datasets" without publishing the result; Phani's paper does not state threshold values at all. Every threshold reported in 3.4.2–3.4.3 above was therefore calibrated by this study against its own evaluation dataset, following each paper's own stated methodology where one is given, and is shown in Section 4.1's ROC figures to sit at a defensible point on that baseline's own measured curve.

## 3.5 Parameter Optimization and Justification

This section reports sensitivity results for the five constants read by the running validation service — `MISSING_SIGNAL_PENALTY`, `GEO_MISMATCH_PENALTY`, `CRIT_TLS_PENALTY`, `DEVICE_TLS_MISMATCH_PENALTY`, and `DEVICE_FRESHNESS_WINDOW_DAYS` (`services/validation/app/main.py`) — and the decision thresholds `ALLOW_T`/`DENY_T` (`services/trust/app/decision_engine.py`).

Each constant is swept independently, holding the other four at their baseline value, by replaying real, previously validated session signals through validation → gateway → trust and re-measuring TPR/FPR/precision/F1 at each setting (`scripts/sensitivity_sweep_penalties.py`).

### 3.5.1 Signal Weights, Penalty Constants, and Freshness Window

Base weights start equal across the signal types present in a session and are then renormalized by quality (`Wi = Qi / ΣQi`, Section 3.2.2). SIEM weights `SIEM_HIGH_BUMP` = 0.30, `SIEM_MED_BUMP` = 0.15 were verified against this study's dataset.

The five penalty/window constants were each swept across their plausible range (baseline plus two or three alternative values each), replaying 1,578 previously-validated sessions (378 benign, 1,200 malicious) through validation → gateway → trust at each setting (Figures 3.10–3.14). None of the five constants has a measurable effect on aggregate TPR, FPR, precision, or F1: TPR ranges from 96.55% to 97.02% and FPR remains approximately 2.65% across the entire tested range of every constant, with a maximum F1 spread of 0.002 across all fifteen tested configurations.

Figure 3.15 shows the live distribution of normalized weight Wi across all five signal types over 27,078 validated sessions. GPS and Wi-Fi BSSID cluster around the equal-share baseline (1/5), TLS fingerprint and device posture spread more widely as their consistency/freshness terms vary, and `ip_geo` sits at essentially zero for every session. This is a direct, verified consequence of the dataset rather than a computation error: CIC-IDS2018's public CSV distribution carries no source or destination IP address columns at all (verified against the raw file headers), so `ip_geo` is populated only for the minority of sessions sourced from RBA (which does carry a real IP) — for the remaining sessions it falls back to a synthetic, non-routable placeholder address that GeoLite2 cannot resolve, driving its enrichment trust Es, and therefore its quality Qi and normalized weight Wi, to zero. In this evaluation, `ip_geo` is consequently a near-inactive signal for CIC-IDS2018-sourced sessions; the framework's location-consistency checks are carried almost entirely by GPS and Wi-Fi BSSID for the large majority of the dataset.

This flat sensitivity follows directly from the decision logic: both `decision_engine.py` and `ablation_engine.py` apply an unconditional floor, `risk_score = max(risk_score, ALLOW_T)`, whenever any of a fixed set of actionable reasons — principally the four trained classifiers' outputs — is present, independent of the quality-weighted confidence multiplier these five constants feed into. Because the majority of malicious sessions in this dataset are flagged by a classifier reason before the quality-weighted risk terms are evaluated, sweeping the five constants has little remaining influence on the aggregate outcome; their effect is confined to the smaller set of sessions whose risk depends only on the additive device/TLS/location terms without a classifier or boolean reason firing. Aggregate accuracy in the current architecture is therefore governed primarily by the network-flow classifiers and the enrichment-dependent Spoofing/Tampering checks rather than by the signal-quality penalty constants.

### 3.5.2 Decision Thresholds

`ALLOW_T = 0.24` was selected via ROC analysis of live risk-score data (Figure 3.17; n = 1,999, AUC = 0.976). The true zero-false-positive-rate point in this distribution sits at threshold 0.241 (TPR = 58.91%); one one-hundredth of a threshold unit lower, at the deployed `ALLOW_T = 0.24`, TPR rises to 96.55% at FPR = 2.65%. This step-change reflects the actionable-reason floor described in Section 3.5.1: a large batch of classifier-flagged malicious sessions is floored to exactly 0.24, producing a sharp cliff in the ROC curve rather than a smooth trade-off. `ALLOW_T = 0.24` sits immediately past this cliff, trading a small false-positive rate for the recall gain the cliff represents.

`DENY_T = 0.75` is not reached by any session in the current evaluation set — malicious or benign, TPR = FPR = 0.0% at this threshold (Figure 3.17) — so the framework's deny action is not exercised under current risk magnitudes, a limitation carried into Chapter 4 and Chapter 5.

## 3.6 Evaluation Metrics

The framework is assessed across four dimensions:

1. **Security accuracy** — True Positive Rate, False Positive Rate, Precision, Recall, F1-Score, AUC.
2. **Performance** — decision latency (median, p95, p99).
3. **Usability** — step-up challenge rate.
4. **Privacy** — data-minimization design intent, evaluated in Chapter 4 against what the implementation verifies rather than what it was designed to do.

### 3.6.1 Comparative Evaluation Design

The proposed framework, the ablation configuration (Section 3.2.7), and the Ahmadi/Phani re-implementations are evaluated on the same live-streamed session set under identical conditions. Each session is submitted once to all four frameworks concurrently and scored against the same ground-truth label; there is no train/validation/test split, cross-validation fold, or repeated-trial variance estimate in this evaluation — a single large-sample live comparison (Chapter 4 reports the exact *n*), and that scope is stated as a limitation in Chapter 5. McNemar's test, the appropriate test for paired binary classification outcomes on the same sessions, is used for significance testing in Chapter 4.

Jimmy (2025) is excluded from this quantitative comparison for the reason given in 3.4.1: no published formula exists to reproduce, so a from-scratch implementation would evaluate this study's own design choices under another paper's name, not that paper's method.

## 3.7 Data Generation Integrity: Native Label Sourcing

Session labels are sourced natively from the dataset rather than assigned independently of a row's content. For the four network-attack STRIDE categories (Denial of Service, Elevation of Privilege, Credential Attack, Information Disclosure), the simulator maintains a pool per category, built at load time by classifying each CIC-IDS2018 row by its own real label (`dos_native`, `eop_native`, `credential_native`, `exfil_native`), plus a genuine Benign pool. When a network-attack category is selected for a session, a row is drawn from the matching native pool and passed through unmodified — its label and the real flow telemetry behind it (Section 3.2.6) are exactly as the dataset recorded them.

The three remaining STRIDE categories — Spoofing (a GPS/Wi-Fi geographic mismatch), Tampering (a malicious TLS fingerprint), and Repudiation (an explicit denial-of-action flag) — have no native representation in CIC-IDS2018, a network-traffic dataset with no field capable of expressing a cross-source location disagreement. These three are therefore constructed synthetically, always on top of a row drawn from the genuine Benign pool, with the constructed label matching exactly what was built. This is the only mechanism available for obtaining ground truth for these categories at all, and is distinct from relabelling an already-labelled attack row.

## 3.8 RBA Dataset Addition for Spoofing Ground Truth

CIC-IDS2018's attack taxonomy is network/protocol-layer (DDoS, web attacks, infiltration), and this framework's Spoofing injection (a fixed GPS offset from a known Wi-Fi AP) is synthetic; neither is strong ground truth for the Spoofing category specifically. The RBA dataset [39][40] — real production login data from a large-scale SSO service, with genuine `Is Attack IP` / `Is Account Takeover` labels — is used as a supplementary source for this category, mixed 50/50 with the synthetic method. RBA redacts geolocation to country level in its public release, so GPS is approximated via a country centroid with small jitter, and a "home"-cluster Wi-Fi AP is attached alongside the RBA-derived (foreign) GPS so the GPS-vs-Wi-Fi mismatch check has a genuine cross-source disagreement to detect. The RBA dataset's own documentation states its released values are "plausible, but... totally artificial," synthesized from real production data for privacy reasons; this limitation is disclosed on the same terms as CIC-IDS2018's own synthetic-traffic limitations (Section 2.6).

---
**Citations used in this chapter:** [7] Ahmadi (2025); [8] Jimmy (2025); [10] Phani Kumar Kanuri (2025); [39]/[40] Wiefling et al. (RBA dataset, 2022); [41] Hevner et al. (Design Science in IS Research, 2004); [42] Peffers et al. (Design Science Research Methodology, 2007); [43] Breiman (Random Forests, 2001); [44] Sharafaldin et al. (CIC-IDS2018, 2018). Full reference list in `References.md`.
