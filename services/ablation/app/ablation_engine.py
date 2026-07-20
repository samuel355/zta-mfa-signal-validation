"""
Ablation engine — the same signal vector and detection logic as the proposed
framework, minus the validation layer (enrichment lookups and cross-source
consistency checks) and its Qi=Fi*Ci*Ei signal-quality scoring.

Proposed and ablation both receive the identical 5-signal vector (ip_geo,
gps, wifi_bssid, device_posture, tls_fp) plus the same network_flow
telemetry. Ablation does not get anything that depends on
validation/app/main.py's enrichment step:
  - Spoofing (GPS-vs-WiFi-vs-IP cross-source distance) needs GeoLite2/WiGLE
    lookups to place WiFi/IP on a map before comparing them.
  - TLS tampering needs the JA3 reference-table lookup.
  - Per-signal quality Qi = Fi*Ci*Ei is replaced by a binary presence
    indicator, normalized the same Wi=Qi/sum(Qi) way.

Ablation still gets, since none of it needs enrichment:
  - Repudiation (a flag the simulator sets directly)
  - Posture-outdated (device_posture.patched, read raw)
  - DoS / Elevation-of-Privilege / Credential / Infiltration (the same
    trained Random Forest classifiers, scored on raw network_flow telemetry)
"""

import os
import time
import random
from typing import Dict, Any, Tuple
import logging

import joblib
import numpy as np

logger = logging.getLogger(__name__)

# Same trained classifiers as services/validation/app/main.py — loaded here
# too since detection only needs raw network_flow telemetry, not enrichment.
MODEL_DIR = os.getenv("ML_MODEL_DIR", "/app/models")

def _load_model(name: str):
    path = os.path.join(MODEL_DIR, f"{name}_classifier.joblib")
    try:
        bundle = joblib.load(path)
        print(f"[ABLATION][ML] Loaded {name} classifier: {len(bundle['feature_names'])} features, threshold={bundle['threshold']}")
        return bundle
    except Exception as e:
        print(f"[ABLATION][ML] Failed to load {name} classifier from {path}: {e}")
        return None

DOS_MODEL = _load_model("dos")
EOP_MODEL = _load_model("eop")
CREDENTIAL_MODEL = _load_model("credential")
INFILTRATION_MODEL = _load_model("infiltration")

_SIGNAL_KEYS = ("ip_geo", "gps", "wifi_bssid", "device_posture", "tls_fp")

# Same severity weights as trust/app/decision_engine.py's stride_map.
_STRIDE_MAP = {
    'DOS': 0.30,
    'POLICY_ELEVATION': 0.25,
    'CREDENTIAL_ATTACK': 0.30,
    'EXFILTRATION': 0.30,
    'REPUDIATION': 0.18,
    'POSTURE_OUTDATED': 0.08,
}


def compute_ablation_reasons(signals: Dict[str, Any]) -> Tuple[list, Dict[str, float]]:
    """Same STRIDE-reason detection as validation/app/main.py's
    compute_reasons(), restricted to what's computable from the raw signal alone."""
    R: list = []
    conf: Dict[str, float] = {}

    if signals.get("repudiation") is True:
        R.append("REPUDIATION")
        conf["REPUDIATION"] = 1.0

    dp = signals.get("device_posture") or {}
    patched = dp.get("patched")
    if isinstance(patched, bool) and not patched:
        R.append("POSTURE_OUTDATED")
        conf["POSTURE_OUTDATED"] = 1.0

    exfil = signals.get("exfiltration_telemetry") or {}
    try:
        outbound = float(exfil.get("outbound_bytes", 0))
        baseline = max(1.0, float(exfil.get("baseline_outbound_bytes", 0)))
        if (exfil.get("dlp_alert") is True and exfil.get("sensitive_data_accessed") is True
                and exfil.get("destination_is_new") is True and outbound / baseline >= 10.0):
            R.append("EXFILTRATION")
            conf["EXFILTRATION"] = round(min(1.0, (outbound / baseline) / 25.0), 4)
    except (TypeError, ValueError):
        pass

    nf = signals.get("network_flow") or {}
    if DOS_MODEL is not None and nf:
        x = np.array([[nf.get(f, 0.0) for f in DOS_MODEL["feature_names"]]])
        proba = float(DOS_MODEL["model"].predict_proba(x)[0, 1])
        if proba >= DOS_MODEL["threshold"]:
            R.append("DOS")
            conf["DOS"] = round(proba, 4)

    if EOP_MODEL is not None and nf:
        x = np.array([[nf.get(f, 0.0) for f in EOP_MODEL["feature_names"]]])
        proba = float(EOP_MODEL["model"].predict_proba(x)[0, 1])
        if proba >= EOP_MODEL["threshold"]:
            R.append("POLICY_ELEVATION")
            conf["POLICY_ELEVATION"] = round(proba, 4)

    if CREDENTIAL_MODEL is not None and nf:
        x = np.array([[nf.get(f, 0.0) for f in CREDENTIAL_MODEL["feature_names"]]])
        proba = float(CREDENTIAL_MODEL["model"].predict_proba(x)[0, 1])
        if proba >= CREDENTIAL_MODEL["threshold"]:
            R.append("CREDENTIAL_ATTACK")
            conf["CREDENTIAL_ATTACK"] = round(proba, 4)

    if INFILTRATION_MODEL is not None and nf:
        x = np.array([[nf.get(f, 0.0) for f in INFILTRATION_MODEL["feature_names"]]])
        proba = float(INFILTRATION_MODEL["model"].predict_proba(x)[0, 1])
        if proba >= INFILTRATION_MODEL["threshold"]:
            R.append("EXFILTRATION")
            conf["EXFILTRATION"] = round(proba, 4)

    return R, conf


def compute_binary_weights(signals: Dict[str, Any]) -> Tuple[Dict[str, float], float]:
    """Ablation's stand-in for validation's compute_weights(): Qi collapses
    to a binary presence indicator, normalized the same Wi=Qi/sum(Qi) way.
    H=M/n is the completeness ratio."""
    present = [k for k in _SIGNAL_KEYS if k in signals]
    n = len(_SIGNAL_KEYS)
    m = len(present)
    h = (m / n) if n else 0.0
    if m == 0:
        return {}, 0.0
    w = 1.0 / m
    return {k: w for k in present}, h


# Config for the no-validation-layer configuration
class BaselineThesisConfig:
    # Same policy thresholds as the full framework, so the measured
    # difference is the validation layer, not a more permissive policy.
    MEDIUM_RISK_THRESHOLD = float(os.getenv("ALLOW_T", "0.24"))
    DENY_THRESHOLD = float(os.getenv("DENY_T", "0.75"))
    # Same base gain as trust/app/decision_engine.py's TRUST_BASE_GAIN.
    TRUST_BASE_GAIN = float(os.getenv("TRUST_BASE_GAIN", "0.03"))


class BaselineDecisionEngine:
    """Processes the same raw signals as the proposed framework, with the
    validation layer and its Qi=Fi*Ci*Ei quality scoring removed."""

    def __init__(self):
        self.config = BaselineThesisConfig()
        self.decisions_made = 0
        self.performance_tracker = {
            'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0,
            'stepup_challenges': 0,
            'processing_times': [],
        }

    def process_signals(self, raw_signals: Dict[str, Any]) -> Dict[str, Any]:
        """Process raw signals with the validation layer and quality scoring removed."""
        start_time = time.perf_counter()

        session_id = raw_signals.get('session_id', f'baseline-{int(time.time())}-{random.randint(1000, 9999)}')

        risk_score, risk_factors = self._calculate_risk(raw_signals)

        decision_result = self._make_baseline_decision(
            session_id=session_id,
            risk_score=risk_score,
            risk_factors=risk_factors,
            raw_signals=raw_signals
        )

        processing_time_ms = int((time.perf_counter() - start_time) * 1000)
        decision_result['processing_time_ms'] = processing_time_ms

        self._update_performance_metrics(decision_result, raw_signals)

        return self._format_thesis_response(decision_result, raw_signals)

    def _calculate_device_posture_risk(self, device_info: Dict[str, Any], weight: float) -> float:
        """Identical to trust/app/decision_engine.py's version — reads only
        the raw device_posture signal, no enrichment lookup involved."""
        if not device_info:
            return 0.1
        device_id = device_info.get('device_id', '')
        patched = device_info.get('patched', True)
        if not device_id:
            return 0.15
        indicator = 0.0
        if not patched:
            indicator += 0.6
        if 'unknown' in device_id.lower():
            indicator += 0.3
        return min(0.3, indicator * weight)

    def _calculate_tls_validated_risk(self, tls_info: Dict[str, Any], weight: float) -> float:
        """Identical to trust/app/decision_engine.py's version — reads only
        raw ja3 presence, no reference-table lookup."""
        if not tls_info or not tls_info.get('ja3', ''):
            return 0.02
        return round(max(0.0, 0.2 - weight) * 0.5, 4)

    def _calculate_stride_risk(self, reasons: list, reason_confidence: Dict[str, float], h: float) -> float:
        """Same structure as trust/app/decision_engine.py's
        _calculate_stride_risk, with H standing in for the Qi-derived
        confidence multiplier."""
        total = 0.0
        for r in reasons:
            w = _STRIDE_MAP.get(r)
            if w is not None:
                total += w * h * reason_confidence.get(r, 1.0)
        return min(0.4, total)

    def _calculate_risk(self, signals: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
        """Ablation's analogue of _calculate_validated_risk: same additive
        structure, binary Wi instead of quality-scored Wi, no location-risk
        term (that's a cross-source check and needs the validation layer)."""
        weights, h = compute_binary_weights(signals)
        avg_weight = 1.0 / len(_SIGNAL_KEYS)

        device_risk = self._calculate_device_posture_risk(
            signals.get('device_posture', {}), weights.get('device_posture', avg_weight))
        tls_risk = self._calculate_tls_validated_risk(
            signals.get('tls_fp', {}), weights.get('tls_fp', avg_weight))

        reasons, reason_confidence = compute_ablation_reasons(signals)
        stride_risk = self._calculate_stride_risk(reasons, reason_confidence, h)

        risk_score = self.config.TRUST_BASE_GAIN + device_risk + tls_risk + stride_risk
        actionable = {
            'REPUDIATION', 'DOS', 'POLICY_ELEVATION',
            'CREDENTIAL_ATTACK', 'EXFILTRATION',
        }
        if any(reason in actionable for reason in reasons):
            risk_score = max(risk_score, self.config.MEDIUM_RISK_THRESHOLD)
        risk_score = max(0.0, min(1.0, risk_score))

        risk_factors = {
            "reasons": reasons,
            "reason_confidence": reason_confidence,
            "signals_present": sorted(weights.keys()),
            "signals_total": len(_SIGNAL_KEYS),
            "H": round(h, 4),
        }
        return risk_score, risk_factors

    def _make_baseline_decision(self, session_id: str, risk_score: float,
                              risk_factors: Dict[str, Any], raw_signals: Dict[str, Any]) -> Dict[str, Any]:
        """Naive two-threshold decision. predicted_threat_level mirrors
        `decision` (step_up/deny -> 'malicious', allow -> 'benign')."""

        label = raw_signals.get('label', '').upper()
        is_benign = label == 'BENIGN'
        actual_threat_level = 'benign' if is_benign else 'malicious'

        if risk_score >= self.config.DENY_THRESHOLD:
            decision = 'deny'
            enforcement = 'DENY'
            requires_stepup = False
        elif risk_score >= self.config.MEDIUM_RISK_THRESHOLD:
            decision = 'step_up'
            enforcement = 'MFA_REQUIRED'
            requires_stepup = True
        else:
            decision = 'allow'
            enforcement = 'ALLOW'
            requires_stepup = False

        predicted_threat_level = 'malicious' if decision in ('step_up', 'deny') else 'benign'

        is_tp = (actual_threat_level == 'malicious' and predicted_threat_level == 'malicious')
        is_fp = (actual_threat_level == 'benign' and predicted_threat_level == 'malicious')
        is_tn = (actual_threat_level == 'benign' and predicted_threat_level == 'benign')
        is_fn = (actual_threat_level == 'malicious' and predicted_threat_level == 'benign')

        return {
            'session_id': session_id,
            'decision': decision,
            'enforcement': enforcement,
            'risk_score': round(risk_score, 3),
            'requires_stepup': requires_stepup,
            'actual_threat_level': actual_threat_level,
            'predicted_threat_level': predicted_threat_level,
            'is_true_positive': is_tp,
            'is_false_positive': is_fp,
            'is_true_negative': is_tn,
            'is_false_negative': is_fn,
            'risk_factors': risk_factors,
            'framework_type': 'ablation',
            'validation_applied': False,
            'enrichment_applied': False
        }

    def _update_performance_metrics(self, decision_result: Dict[str, Any], raw_signals: Dict[str, Any]):
        """Update performance tracking for thesis metrics"""
        self.decisions_made += 1

        if decision_result.get('is_true_positive'):
            self.performance_tracker['tp'] += 1
        elif decision_result.get('is_false_positive'):
            self.performance_tracker['fp'] += 1
        elif decision_result.get('is_true_negative'):
            self.performance_tracker['tn'] += 1
        elif decision_result.get('is_false_negative'):
            self.performance_tracker['fn'] += 1

        if decision_result.get('requires_stepup'):
            self.performance_tracker['stepup_challenges'] += 1

        processing_time = decision_result.get('processing_time_ms', 120)
        self.performance_tracker['processing_times'].append(processing_time)

    def _format_thesis_response(self, decision_result: Dict[str, Any], raw_signals: Dict[str, Any]) -> Dict[str, Any]:
        """Format response for dashboard and metrics collection"""

        metrics = self._calculate_running_metrics()

        response = {
            'session_id': decision_result['session_id'],
            'framework_type': 'ablation',
            'decision': decision_result['decision'],
            'enforcement': decision_result['enforcement'],
            'risk_score': decision_result['risk_score'],

            'thesis_metrics': {
                'tpr': metrics['tpr'],
                'fpr': metrics['fpr'],
                'precision': metrics['precision'],
                'recall': metrics['recall'],
                'f1_score': metrics['f1_score'],
                'stepup_challenge_rate_pct': metrics['stepup_rate'],
                'processing_time_ms': decision_result.get('processing_time_ms', 120),
                'avg_decision_latency_ms': metrics['avg_latency']
            },

            'details': {
                'actual_threat_level': decision_result['actual_threat_level'],
                'predicted_threat_level': decision_result['predicted_threat_level'],
                'risk_factors': decision_result['risk_factors'],
                'validation_applied': False,
                'enrichment_applied': False,
                'signal_quality_score': decision_result['risk_factors'].get('H'),
            },

            'performance': {
                'decisions_made': self.decisions_made,
                'true_positives': self.performance_tracker['tp'],
                'false_positives': self.performance_tracker['fp'],
                'true_negatives': self.performance_tracker['tn'],
                'false_negatives': self.performance_tracker['fn']
            }
        }

        return response

    def _calculate_running_metrics(self) -> Dict[str, float]:
        """TPR/FPR/etc from this process's tp/fp/tn/fn tallies."""
        tp = self.performance_tracker['tp']
        fp = self.performance_tracker['fp']
        tn = self.performance_tracker['tn']
        fn = self.performance_tracker['fn']

        total_decisions = max(1, tp + fp + tn + fn)

        tpr = (tp / max(1, tp + fn)) if (tp + fn) > 0 else 0.0
        fpr = (fp / max(1, fp + tn)) if (fp + tn) > 0 else 0.0
        precision = (tp / max(1, tp + fp)) if (tp + fp) > 0 else 0.0
        recall = tpr

        f1_score = (2 * precision * recall / max(0.001, precision + recall)) if (precision + recall) > 0 else 0.0

        stepup_rate = (self.performance_tracker['stepup_challenges'] / max(1, total_decisions)) * 100

        avg_latency = sum(self.performance_tracker['processing_times']) / max(1, len(self.performance_tracker['processing_times'])) if self.performance_tracker['processing_times'] else 0.0

        return {
            'tpr': round(tpr, 3),
            'fpr': round(fpr, 3),
            'precision': round(precision, 3),
            'recall': round(recall, 3),
            'f1_score': round(f1_score, 3),
            'stepup_rate': round(stepup_rate, 2),
            'avg_latency': round(avg_latency, 1)
        }

    def get_thesis_summary(self) -> Dict[str, Any]:
        """Summary for the live dashboard, from this process's in-memory tally."""
        metrics = self._calculate_running_metrics()

        return {
            'framework_type': 'ablation',
            'total_decisions': self.decisions_made,
            'current_metrics': metrics,
            'capabilities': {
                'validation_layer': False,
                'enrichment_engine': False,
                'signal_quality_assessment': False,
                'cross_signal_validation': False,
            }
        }

# Global instance for thesis demonstration
baseline_engine = BaselineDecisionEngine()

def process_baseline_request(signals: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for baseline framework processing.
    This function is called by the baseline service to generate thesis-compliant results.
    """
    return baseline_engine.process_signals(signals)

def get_baseline_thesis_metrics() -> Dict[str, Any]:
    """Get current thesis metrics for baseline framework"""
    return baseline_engine.get_thesis_summary()

def reset_baseline_metrics():
    """Reset performance tracking (useful for demonstrations)"""
    global baseline_engine
    baseline_engine = BaselineDecisionEngine()
    logger.info("Baseline thesis engine metrics reset")
