# Chapter 5 — Discussion, Limitations, Conclusion: Reference Notes

## Baseline comparison: self-reported vs independently verified

Both baseline papers report a single "Detection Accuracy" figure on their
own private, unreleased, self-generated simulated data:

- **Ahmadi (2025)**, Table 6: 92.7% detection accuracy, 6.3% FPR (own
  ~10,000-session simulated dataset, never released).
- **Phani (2025)**, Section IV: 96.8% access decision accuracy (own
  simulated dataset, never released; note the paper's own Figure 2 pie
  chart, 57.6%/42.4%, doesn't actually match this stated 96.8%/71.3% —
  an internal inconsistency in their own reporting, worth noting).

Neither number is independently reproducible — no dataset, code, or
methodology detail was published that would let a third party verify them.
This thesis's baseline TPR figures (Ahmadi 21.86%, Phani 6.11%) measure
something different and are **not directly comparable** to those headline
numbers: this thesis re-implements each paper's *published equation* exactly
and tests it against a real, disclosed, reproducible dataset (CIC-IDS2018 +
RBA), whereas the original papers report performance on data nobody else
can access. State this explicitly rather than letting the gap look like an
implementation flaw — it's a structural consequence of comparing an
independently-verified reproduction against self-reported, unverifiable
claims, and is itself a defensible point about this thesis's methodological
rigor relative to the literature it's building on.

## CIC-IDS2018 vs an authentication-native dataset — an honest limitation

CIC-IDS2018 is a network-intrusion dataset (DDoS, port scans, web attacks,
botnet traffic) being used as ground truth for a *session-level
authentication decision* framework. Most of its attack categories are
protocol/network-layer events that don't manifest in any
context-validation signal (GPS, device posture, TLS, WiFi) — which is
exactly why Ahmadi and Phani score so low once label leakage is removed
(see Chapter 4, Figure 4.5): their equations were never designed to see
these attack types, regardless of implementation quality.

This was mitigated for one category (Spoofing) by adding real RBA
account-takeover ground truth (Chapter 3.7), but the other five STRIDE
categories still rely on CIC-IDS2018. Two datasets considered but not
integrated, for future work:

- **LANL "Comprehensive, Multi-Source Cyber-Security Events"** — real
  enterprise authentication events (source/dest user, computer, auth type,
  success/failure) with labeled red-team malicious events. Structurally the
  closest match to this framework's actual decision unit (a login/access
  attempt with contextual signals), but integrating it would require
  rebuilding the STRIDE mapping, simulator, and DB schema — a large
  undertaking not attempted this cycle.
- **CERT Insider Threat Dataset** — synthetic-but-realistic logon/device/
  email/file event streams with labeled malicious insiders; better suited to
  the Repudiation/EoP/Information-Disclosure STRIDE categories than
  CIC-IDS2018's network-attack framing. Also not integrated.

## Session-continuity metric

The abstract's claim that "session continuity reaches 95%" has no
corresponding measurement anywhere in this codebase — the current
architecture evaluates single-shot sessions, not continuous multi-request
sessions, so "session continuity" as stated is not something the current
simulator design can measure at all. Recommend either removing this claim
or explicitly scoping it as future work requiring a session-continuity
experiment that doesn't exist yet.

## CIC-IDS2018 naming

The original document refers to "CICIDS2017" in 11 places despite using the
2018 dataset throughout. Needs a global find-and-replace to "CIC-IDS2018"
during the manual rewrite.

## Network condition sensitivity — needs a rerun

`scripts/simulator/network_condition_experiment.py` was last run before this
cycle's threshold/calibration fixes (normal=680.2ms/TPR=61.0%,
constrained=807.2ms/TPR=62.1%, degraded=875.5ms/TPR=62.2%, n=150/condition).
These numbers are currently what Figure 4.2's network-condition panel shows,
but they reflect the framework's *pre-fix* TPR (~61%, when the real
post-fix aggregate TPR is 88.30%) — internally inconsistent with the rest of
Chapter 4 and should be rerun before final submission, or the panel should
carry an explicit "measured before final calibration" caveat if a rerun
isn't feasible in the remaining time.

## Future work items surfaced this cycle (for the thesis's own Future Work section)

1. Real component-level ablation (toggle individual validation checks —
   TLS, WiFi cross-check, device posture — independently, rather than only
   the binary "validation layer on/off" comparison the `ablation` framework
   already provides).
2. LANL and/or CERT dataset integration for authentication-native ground
   truth across all six STRIDE categories, not just Spoofing.
3. A genuine session-continuity experiment (multi-request session tracking)
   to support or retire the abstract's continuity claim.
4. Rerun network-condition sensitivity experiment under current calibration.
