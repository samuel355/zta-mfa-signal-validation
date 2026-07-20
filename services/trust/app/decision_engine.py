"""
Decision engine for the proposed framework.

Turns validated signals (device posture, STRIDE reasons, SIEM alert counts,
validation confidence) into a risk score and an allow/step_up/deny decision.
"""

import time
import json
import random
import os
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timedelta
import logging
import math

logger = logging.getLogger(__name__)

# Config for the proposed framework
class ProposedThesisConfig:
    # Decision thresholds from ROC sweep against live risk scores.
    LOW_RISK_THRESHOLD = float(os.getenv('ALLOW_T', '0.24'))
    MEDIUM_RISK_THRESHOLD = LOW_RISK_THRESHOLD
    HIGH_RISK_THRESHOLD = float(os.getenv('DENY_T', '0.75'))
    DENY_THRESHOLD = float(os.getenv('DENY_T', '0.75'))

    # 5 signal types max, so confidence values cap at 1.0.
    MIN_VALIDATION_CONFIDENCE = float(os.getenv('VALIDATION_CONFIDENCE_THRESHOLD', '0.70'))
    HIGH_VALIDATION_CONFIDENCE = 0.90
    ENRICHMENT_QUALITY_THRESHOLD = 0.75

    # SIEM alert bumps
    SIEM_HIGH_BUMP = float(os.getenv('SIEM_HIGH_BUMP', '0.30'))
    SIEM_MED_BUMP = float(os.getenv('SIEM_MED_BUMP', '0.15'))

    # Base risk before any signal-specific contribution
    TRUST_BASE_GAIN = float(os.getenv('TRUST_BASE_GAIN', '0.03'))
    # Confidence when there are no weighted signals at all
    TRUST_FALLBACK_OBSERVED = float(os.getenv('TRUST_FALLBACK_OBSERVED', '0.05'))

class ProposedDecisionEngine:
    """Proposed decision engine: computes risk_score from real signal-derived
    inputs (see module docstring) and thresholds it into allow/step_up/deny."""

    def __init__(self):
        self.config = ProposedThesisConfig()
        self.decisions_made = 0
        self.validation_cache = {}
        self.performance_tracker = {
            'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0,
            'stepup_challenges': 0,
            'processing_times': [],
            'validation_scores': [],
        }

    def process_validated_signals(self, validated_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process validated and enriched signals from the validation service.
        This is the key differentiator from the baseline framework.
        """
        start_time = time.perf_counter()

        # Extract validated components
        vector = validated_context.get('vector', {})
        weights = validated_context.get('weights', {})
        reasons = validated_context.get('reasons', [])
        reason_confidence = validated_context.get('reason_confidence', {}) or {}
        siem_data = validated_context.get('siem', {})
        quality_confidence = validated_context.get('quality_confidence')
        checks = validated_context.get('checks', {})

        session_id = vector.get('session_id', f'proposed-{int(time.time())}-{random.randint(1000, 9999)}')

        # Validation Quality Assessment
        validation_quality = self._assess_validation_quality(weights, reasons, quality_confidence)

        # Enhanced Risk Calculation (with validation confidence)
        risk_score = self._calculate_validated_risk(vector, weights, reasons, reason_confidence, siem_data, validation_quality, checks)

        # Enhanced Decision Logic
        decision_result = self._make_enhanced_decision(
            session_id=session_id,
            risk_score=risk_score,
            validation_quality=validation_quality,
            reasons=reasons,
            vector=vector,
            siem_data=siem_data
        )

        # This service can only measure its own scoring time. End-to-end
        # validation + gateway + trust latency is measured by the simulator.
        processing_time_ms = int((time.perf_counter() - start_time) * 1000)
        decision_result['processing_time_ms'] = processing_time_ms

        # Update performance metrics
        self._update_performance_metrics(decision_result, vector, validation_quality)

        # Generate thesis-compliant response
        return self._format_thesis_response(decision_result, validated_context, validation_quality)

    def _assess_validation_quality(self, weights: Dict[str, float], reasons: List[str],
                                   quality_confidence: Optional[float]) -> Dict[str, float]:
        """How much do we trust this session's signals?

        signal_coverage is validation's quality_confidence — the average of
        each present signal's penalty multiplier.
        """
        if not weights:
            # nothing to go on — assume low confidence, not moderate
            return {'overall_confidence': self.config.TRUST_FALLBACK_OBSERVED, 'signal_coverage': 0.3, 'validation_strength': 0.4}

        signal_coverage = min(1.0, quality_confidence) if quality_confidence is not None else min(1.0, sum(weights.values()) / 1.5)

        # how many of the 5 possible signal types did we actually get?
        validation_strength = min(1.0, len(weights) / 5.0)

        overall_confidence = (signal_coverage * 0.6) + (validation_strength * 0.4)

        return {
            'overall_confidence': round(overall_confidence, 3),
            'signal_coverage': round(signal_coverage, 3),
            'validation_strength': round(validation_strength, 3)
        }

    def _calculate_validated_risk(self, vector: Dict[str, Any], weights: Dict[str, float],
                                 reasons: List[str], reason_confidence: Dict[str, float],
                                 siem_data: Dict[str, Any],
                                 validation_quality: Dict[str, float],
                                 checks: Dict[str, Any] = None) -> float:
        """Calculate risk score with validation confidence weighting"""

        # Base risk calculation with validation confidence
        confidence_multiplier = validation_quality['overall_confidence']
        base_risk = self.config.TRUST_BASE_GAIN  # Lower base risk due to validation
        checks = checks or {}

        # Process validated signals with confidence weighting
        risk_score = base_risk

        # risk_score never reads vector['label'] — that's ground truth,
        # reserved for scoring in _make_enhanced_decision below.

        # Device/location/TLS contributions are each scaled by that signal's
        # own Wi from validation's Qs=Fs*Cs*Es scoring, not the flat overall
        # confidence used above.
        avg_weight = 1.0 / 5.0

        device_risk = self._calculate_device_posture_risk(vector.get('device_posture', {}), weights.get('device_posture', avg_weight))
        risk_score += device_risk

        # Enhanced location validation with cross-reference
        location_w = weights.get('gps', weights.get('wifi_bssid', avg_weight))
        location_risk = self._calculate_location_validation_risk(vector.get('gps', {}), vector.get('wifi_bssid', {}), checks, location_w)
        risk_score += location_risk

        # Enhanced TLS fingerprint analysis with threat intelligence
        tls_risk = self._calculate_tls_validated_risk(vector.get('tls_fp', {}), weights.get('tls_fp', avg_weight))
        risk_score += tls_risk

        # Apply STRIDE-based risk factors with validation confidence
        stride_risk = self._calculate_stride_risk(reasons, reason_confidence, confidence_multiplier)
        risk_score += stride_risk

        # SIEM integration with validation
        siem_risk = self._calculate_siem_risk(siem_data, confidence_multiplier)
        risk_score += siem_risk

        # Only discount risk for sessions that are both complete AND clean.
        if not reasons and confidence_multiplier >= self.config.HIGH_VALIDATION_CONFIDENCE:
            risk_score *= 0.75
        elif confidence_multiplier <= 0.5:
            risk_score *= 1.1

        actionable = {
            'SPOOFING', 'GPS_MISMATCH', 'WIFI_MISMATCH', 'TLS_ANOMALY',
            'REPUDIATION', 'DOS', 'POLICY_ELEVATION', 'CREDENTIAL_ATTACK',
            'EXFILTRATION', 'DOWNLOAD_EXFIL',
        }
        if any(any(code in str(reason).upper() for code in actionable) for reason in reasons):
            risk_score = max(risk_score, self.config.LOW_RISK_THRESHOLD)

        return max(0.0, min(1.0, risk_score))

    def _calculate_device_posture_risk(self, device_info: Dict[str, Any], weight: float) -> float:
        """Device posture risk, scaled by that signal's own Wi (Qi/sum(Qi)
        from validation — freshness x consistency x enrichment)."""
        if not device_info:
            return 0.1

        device_id = device_info.get('device_id', '')
        patched = device_info.get('patched', True)

        if not device_id:
            return 0.15

        indicator = 0.0
        # Unpatched devices are higher risk
        if not patched:
            indicator += 0.6
        # Unknown devices get some risk but validation helps classify them better
        if 'unknown' in device_id.lower():
            indicator += 0.3

        return min(0.3, indicator * weight)

    def _calculate_location_validation_risk(self, gps: Dict[str, Any], wifi: Dict[str, Any],
                                             checks: Dict[str, Any], weight: float) -> float:
        """Continuous, distance-based location risk, scaled by the location
        signal's own Wi. `checks` carries the gps_wifi/gps_ip haversine
        distances from validation's enrichment step."""
        if not gps or not wifi:
            return 0.05

        lat = gps.get('lat', 0)
        lon = gps.get('lon', 0)
        bssid = wifi.get('bssid', '')

        if not bssid or not lat or not lon:
            return 0.08

        dist = None
        for k in ("gps_wifi_distance_km", "gps_ip_distance_km"):
            v = (checks or {}).get(k)
            if isinstance(v, (int, float)):
                dist = v if dist is None else min(dist, v)
        if dist is None:
            return 0.0

        threshold = (checks or {}).get("threshold_km", 50.0) or 50.0
        # Distances beyond 3x the mismatch threshold score as maximally suspicious.
        normalized = min(1.0, dist / (threshold * 3.0))
        return round(normalized * 0.25 * weight, 4)

    def _calculate_tls_validated_risk(self, tls_info: Dict[str, Any], weight: float) -> float:
        """Missing TLS data is a small flat risk. Present-but-low-Wi TLS data
        (down-weighted for a critical JA3 tag or platform mismatch) adds a
        proportionally larger nudge."""
        if not tls_info or not tls_info.get('ja3', ''):
            return 0.02
        return round(max(0.0, 0.2 - weight) * 0.5, 4)

    def _calculate_stride_risk(self, reasons: List[str], reason_confidence: Dict[str, float],
                                confidence: float) -> float:
        """STRIDE-based risk with validation confidence.

        Each reason's fixed weight below is the ceiling it contributes;
        reason_confidence (from validation's compute_reasons) scales it down
        for weaker evidence — a classifier's predict_proba, or a normalized
        haversine distance for location-based reasons. Categorical reasons
        (TLS_ANOMALY, POSTURE_OUTDATED, REPUDIATION) get full weight (1.0),
        since there's no continuous strength to report for a boolean flag.
        """
        stride_map = {
            'SPOOFING': 0.12,
            'DOS': 0.30,
            'DDOS': 0.30,
            'POLICY_ELEVATION': 0.25,
            'CREDENTIAL_ATTACK': 0.30,
            'EXFILTRATION': 0.30,
            'DOWNLOAD_EXFIL': 0.20,
            'TLS_ANOMALY': 0.15,
            'POSTURE_OUTDATED': 0.08,
            'REPUDIATION': 0.18,
            'GPS_MISMATCH': 0.06,
            'WIFI_MISMATCH': 0.04
        }

        total_risk = 0.0
        for reason in reasons:
            reason_upper = str(reason).upper()
            detection_confidence = reason_confidence.get(reason, 1.0)
            for stride_pattern, risk_value in stride_map.items():
                if stride_pattern in reason_upper:
                    # Apply both validation confidence and this specific
                    # detection's own evidence strength.
                    adjusted_risk = risk_value * confidence * detection_confidence
                    total_risk += adjusted_risk

        return min(0.4, total_risk)  # Cap STRIDE risk

    def _calculate_siem_risk(self, siem_data: Dict[str, Any], confidence: float) -> float:
        """Calculate SIEM-based risk with validation confidence"""
        if not siem_data:
            return 0.0

        high_alerts = siem_data.get('high', 0)
        medium_alerts = siem_data.get('medium', 0)

        # SIEM risk calculation with validation confidence
        siem_risk = (high_alerts * self.config.SIEM_HIGH_BUMP + medium_alerts * self.config.SIEM_MED_BUMP) * confidence

        return min(0.3, siem_risk)

    def _make_enhanced_decision(self, session_id: str, risk_score: float,
                               validation_quality: Dict[str, float],
                               reasons: List[str], vector: Dict[str, Any],
                               siem_data: Dict[str, Any]) -> Dict[str, Any]:
        """Turn the risk score into allow/step_up/deny. predicted_threat_level
        mirrors that decision (step_up/deny -> 'malicious', allow -> 'benign')."""

        label = vector.get('label', '').upper()
        is_benign = label == 'BENIGN'
        actual_threat_level = 'benign' if is_benign else 'malicious'

        confidence = validation_quality['overall_confidence']

        # Strict policy: allow < ALLOW_T, step_up in [ALLOW_T, DENY_T), deny >= DENY_T
        allow_t = self.config.LOW_RISK_THRESHOLD
        deny_t = self.config.DENY_THRESHOLD
        if risk_score >= deny_t:
            decision = 'deny'
            enforcement = 'DENY'
            requires_stepup = False
        elif risk_score < allow_t:
            decision = 'allow'
            enforcement = 'ALLOW'
            requires_stepup = False
        else:
            decision = 'step_up'
            enforcement = 'MFA_REQUIRED'
            requires_stepup = True

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
            'validation_confidence': confidence,
            'reasons': reasons,
            'framework_type': 'proposed',
            'validation_applied': True,
            'enrichment_applied': True
        }

    def _update_performance_metrics(self, decision_result: Dict[str, Any], vector: Dict[str, Any],
                                   validation_quality: Dict[str, float]):
        """In-memory tally for this process, backing GET /metrics and GET /compare."""
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

        processing_time = decision_result.get('processing_time_ms', 150)
        self.performance_tracker['processing_times'].append(processing_time)

        self.performance_tracker['validation_scores'].append(validation_quality['overall_confidence'])

    def _format_thesis_response(self, decision_result: Dict[str, Any], validated_context: Dict[str, Any],
                               validation_quality: Dict[str, float]) -> Dict[str, Any]:
        """Format response for thesis dashboard and metrics collection"""

        # Calculate current running metrics
        metrics = self._calculate_running_metrics()

        response = {
            'session_id': decision_result['session_id'],
            'framework_type': 'proposed',
            'decision': decision_result['decision'],
            'enforcement': decision_result['enforcement'],
            'risk_score': decision_result['risk_score'],

            # Fields with no real measurement behind them are left out.
            'thesis_metrics': {
                'tpr': metrics['tpr'],
                'fpr': metrics['fpr'],
                'precision': metrics['precision'],
                'recall': metrics['recall'],
                'f1_score': metrics['f1_score'],
                'stepup_challenge_rate_pct': metrics['stepup_rate'],
                'processing_time_ms': decision_result.get('processing_time_ms', 150),
                'avg_decision_latency_ms': metrics['avg_latency']
            },

            # Decision Details
            'details': {
                'actual_threat_level': decision_result['actual_threat_level'],
                'predicted_threat_level': decision_result['predicted_threat_level'],
                'reasons': decision_result['reasons'],
                'validation_applied': True,
                'enrichment_applied': True,
                'signal_quality_score': validation_quality['overall_confidence'],
                'confidence_score': validation_quality['overall_confidence'],
                'validation_confidence': decision_result['validation_confidence']
            },

            # Validation Metrics
            'validation_metrics': {
                'signal_coverage': validation_quality['signal_coverage'],
                'validation_strength': validation_quality['validation_strength'],
                'overall_confidence': validation_quality['overall_confidence'],
            },

            # Performance Tracking
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

        avg_validation_score = sum(self.performance_tracker['validation_scores']) / max(1, len(self.performance_tracker['validation_scores'])) if self.performance_tracker['validation_scores'] else 0.0

        return {
            'framework_type': 'proposed',
            'total_decisions': self.decisions_made,
            'current_metrics': metrics,
            'validation_metrics': {
                'average_validation_confidence': round(avg_validation_score, 3),
            },
            'capabilities': {
                'validation_layer': True,
                'enrichment_engine': True,
                'signal_quality_assessment': True,
                'cross_signal_validation': True,
            }
        }

# Global instance for thesis demonstration
proposed_engine = ProposedDecisionEngine()

def process_proposed_request(validated_context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for proposed framework processing.
    This function is called by the trust service to generate thesis-compliant results.
    """
    return proposed_engine.process_validated_signals(validated_context)

def get_proposed_thesis_metrics() -> Dict[str, Any]:
    """Get current thesis metrics for proposed framework"""
    return proposed_engine.get_thesis_summary()

def reset_proposed_metrics():
    """Reset performance tracking (useful for demonstrations)"""
    global proposed_engine
    proposed_engine = ProposedDecisionEngine()
    logger.info("Proposed thesis engine metrics reset")

def compare_frameworks() -> Dict[str, Any]:
    """Dashboard comparison. 'proposed' is this process's live in-memory
    tally; the other frameworks run in separate containers, so their rows are
    static snapshots from the last full run's chapter4_metrics.json.
    scripts/compute_chapter4_metrics.py querying the DB directly is the
    source of truth for anything reported."""
    proposed_metrics = get_proposed_thesis_metrics()

    return {
        'comparison_timestamp': datetime.utcnow().isoformat(),
        'static_snapshot_as_of': '2026-07-19T19:49:50Z',
        'frameworks': {
            'proposed': {
                'tpr': proposed_metrics['current_metrics']['tpr'],
                'fpr': proposed_metrics['current_metrics']['fpr'],
                'precision': proposed_metrics['current_metrics']['precision'],
                'stepup_rate': proposed_metrics['current_metrics']['stepup_rate'],
            },
            # Internal ablation study: proposed pipeline without the validation layer.
            'ablation': {
                'tpr': 0.0,
                'fpr': 0.0,
                'precision': 0.0,
                'stepup_rate': 0.0,
            },
            # Published baseline reproductions.
            'ahmadi2025': {'tpr': 0.1943, 'fpr': 0.0916, 'precision': 0.8902, 'stepup_rate': 9.15},
            'phani2025':  {'tpr': 0.1009, 'fpr': 0.0217, 'precision': 0.9467, 'stepup_rate': 0.55},
            # No published risk-scoring formula for jimmy2025 — excluded from comparison.
            'jimmy2025':  {'tpr': None, 'fpr': None, 'precision': None, 'stepup_rate': None},
        }
    }
