from fastapi import FastAPI, Query
from pydantic import BaseModel
from typing import Dict, Any, Optional
import os
from datetime import datetime
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
import logging
from .framework_metrics import ThesisMetricsCalculator

api = FastAPI(title="Metrics Collection Service", version="1.0")

logger = logging.getLogger(__name__)
_engine: Optional[Engine] = None

class MetricsResponse(BaseModel):
    security_metrics: Dict[str, Any]
    performance_metrics: Dict[str, Any]
    detection_metrics: Dict[str, Any]
    decision_metrics: Dict[str, Any]
    timestamp: str

def _mask_dsn(dsn: str) -> str:
    try:
        at = dsn.find('@')
        if '://' in dsn and at != -1:
            head, tail = dsn.split('://', 1)
            creds, rest = tail.split('@', 1)
            if ':' in creds:
                user, _ = creds.split(':', 1)
                return f"{head}://{user}:***@{rest}"
    except Exception:
        pass
    return dsn

def get_engine() -> Optional[Engine]:
    global _engine
    if _engine is not None:
        return _engine
    dsn = os.getenv("DB_DSN", "").strip()
    if not dsn:
        print("[METRICS][DB] DB_DSN missing; cannot collect metrics")
        return None
    if dsn.startswith("postgresql://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgresql://"):]
    elif dsn.startswith("postgres://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgres://"):]
    if "sslmode=" not in dsn:
        dsn += ("&" if "?" in dsn else "?") + "sslmode=require"
    try:
        _engine = create_engine(dsn, pool_pre_ping=True, future=True,
                                 pool_size=3, max_overflow=3,
                                 connect_args={"prepare_threshold": None})
        _warm_pool(_engine, 3)
        print(f"[METRICS][DB] Engine created OK for {_mask_dsn(dsn)}")
    except Exception as e:
        print(f"[METRICS][DB] Failed to create engine "
              f"for {_mask_dsn(dsn)}: {e}")
        _engine = None
    return _engine

def _warm_pool(engine: Engine, n: int):
    """Eagerly open N pooled connections at startup — see validation service for rationale."""
    conns = []
    try:
        for _ in range(n):
            c = engine.connect()
            c.execute(text("select 1"))
            conns.append(c)
    finally:
        for c in conns:
            c.close()

def calculate_security_metrics(hours: int = 24) -> Dict[str, Any]:
    """Calculate security-related metrics"""
    eng = get_engine()
    if eng is None:
        return {"error": "database unavailable — no metrics to report"}

    try:
        with eng.connect() as conn:
            # Authentication outcomes
            auth_stats = conn.execute(text(f"""
                SELECT outcome, COUNT(*) as count
                FROM zta.mfa_events
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                GROUP BY outcome
            """)).mappings().all()

            # Risk distribution
            risk_dist = conn.execute(text(f"""
                SELECT
                    CASE
                        WHEN (detail::jsonb->>'risk')::float < 0.3 THEN 'low'
                        WHEN (detail::jsonb->>'risk')::float < 0.7 THEN 'medium'
                        ELSE 'high'
                    END as risk_level,
                    COUNT(*) as count
                FROM zta.mfa_events
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                AND detail::jsonb->>'risk' IS NOT NULL
                GROUP BY risk_level
            """)).mappings().all()

            # MFA step-up effectiveness
            stepup_stats = conn.execute(text(f"""
                SELECT
                    (detail::jsonb->>'enforcement') as enforcement,
                    COUNT(*) as count,
                    AVG((detail::jsonb->>'risk')::float) as avg_risk
                FROM zta.mfa_events
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                AND detail::jsonb->>'enforcement' IS NOT NULL
                GROUP BY enforcement
            """)).mappings().all()

            # STRIDE threat detection
            stride_stats = conn.execute(text(f"""
                SELECT
                    stride,
                    severity,
                    COUNT(*) as count
                FROM zta.siem_alerts
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                GROUP BY stride, severity
            """)).mappings().all()

            return {
                "authentication_outcomes": {r["outcome"]: r["count"] for r in auth_stats},
                "risk_distribution": {r["risk_level"]: r["count"] for r in risk_dist},
                "enforcement_actions": [
                    {
                        "enforcement": r["enforcement"],
                        "count": r["count"],
                        "avg_risk": float(r["avg_risk"] or 0)
                    } for r in stepup_stats
                ],
                "stride_detections": [
                    {
                        "stride": r["stride"],
                        "severity": r["severity"],
                        "count": r["count"]
                    } for r in stride_stats
                ]
            }
    except Exception as e:
        return {"error": str(e)}

def calculate_performance_metrics(hours: int = 24) -> Dict[str, Any]:
    """Calculate performance-related metrics"""
    eng = get_engine()
    if eng is None:
        return {"error": "database unavailable — no metrics to report"}

    try:
        with eng.connect() as conn:
            # Decision latency (simulated - would need actual timing data)
            decision_count = conn.execute(text(f"""
                SELECT COUNT(*) as total_decisions
                FROM zta.trust_decisions
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
            """)).scalar()

            # Signal reliability
            signal_stats = conn.execute(text(f"""
                SELECT
                    jsonb_array_elements_text(signals::jsonb->'signals_observed') as signal_type,
                    COUNT(*) as occurrences
                FROM zta.validated_context
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                GROUP BY signal_type
            """)).mappings().all()

            # System throughput
            hourly_throughput = conn.execute(text(f"""
                SELECT
                    DATE_TRUNC('hour', created_at) as hour,
                    COUNT(*) as events
                FROM zta.mfa_events
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                GROUP BY hour
                ORDER BY hour
            """)).mappings().all()

            return {
                "total_decisions": decision_count or 0,
                "signal_reliability": [
                    {"signal_type": r["signal_type"], "occurrences": r["occurrences"]}
                    for r in signal_stats
                ],
                "hourly_throughput": [
                    {"hour": r["hour"].isoformat(), "events": r["events"]}
                    for r in hourly_throughput
                ],
                "avg_throughput_per_hour": (
                    sum(r["events"] for r in hourly_throughput) /
                    max(len(hourly_throughput), 1)
                )
            }
    except Exception as e:
        return {"error": str(e)}

def calculate_detection_metrics(hours: int = 24) -> Dict[str, Any]:
    """Calculate threat detection accuracy metrics"""
    eng = get_engine()
    if eng is None:
        return {"error": "database unavailable — no metrics to report"}

    try:
        with eng.connect() as conn:
            # Threat detection by label (from CIC-IDS2018 dataset)
            threat_detection = conn.execute(text(f"""
                SELECT
                    UPPER(signals::jsonb->'vector'->>'label') as original_label,
                    jsonb_array_length(COALESCE(signals::jsonb->'reasons',
                                              '[]'::jsonb)) as detected_threats,
                    COUNT(*) as count
                FROM zta.validated_context
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                AND signals::jsonb->'vector'->>'label' IS NOT NULL
                GROUP BY original_label, detected_threats
            """)).mappings().all()

            # Signal quality metrics
            quality_metrics = conn.execute(text(f"""
                SELECT
                    jsonb_array_length(quality::jsonb->'missing') as missing_signals,
                    COUNT(*) as count,
                    AVG(jsonb_array_length(COALESCE(signals::jsonb->'reasons',
                                                   '[]'::jsonb))) as avg_threats_detected
                FROM zta.validated_context
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                GROUP BY missing_signals
            """)).mappings().all()

            # Cross-check accuracy
            cross_check_stats = conn.execute(text(f"""
                SELECT
                    (cross_checks::jsonb->>'gps_wifi_far')::boolean
                        as gps_wifi_mismatch,
                    COUNT(*) as count
                FROM zta.validated_context
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                GROUP BY gps_wifi_mismatch
            """)).mappings().all()

            return {
                "threat_detection_by_label": [
                    {
                        "original_label": r["original_label"],
                        "detected_threats": r["detected_threats"],
                        "count": r["count"]
                    } for r in threat_detection
                ],
                "signal_quality": [
                    {
                        "missing_signals": r["missing_signals"],
                        "count": r["count"],
                        "avg_threats_detected": float(
                            r["avg_threats_detected"] or 0
                        )
                    } for r in quality_metrics
                ],
                "cross_check_stats": [
                    {
                        "gps_wifi_mismatch": r["gps_wifi_mismatch"],
                        "count": r["count"]
                    } for r in cross_check_stats
                ]
            }
    except Exception as e:
        return {"error": str(e)}

def calculate_decision_metrics(hours: int = 24) -> Dict[str, Any]:
    """Calculate decision accuracy and effectiveness metrics"""
    eng = get_engine()
    if eng is None:
        return {"error": "database unavailable — no metrics to report"}

    try:
        with eng.connect() as conn:
            # Decision distribution
            decision_dist = conn.execute(text(f"""
                SELECT
                    decision,
                    COUNT(*) as count,
                    AVG(risk) as avg_risk,
                    MIN(risk) as min_risk,
                    MAX(risk) as max_risk
                FROM zta.trust_decisions
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                GROUP BY decision
            """)).mappings().all()

            # Risk vs Decision correlation
            risk_decision_correlation = conn.execute(text(f"""
                SELECT
                    CASE
                        WHEN risk < 0.25 THEN 'low_risk'
                        WHEN risk < 0.70 THEN 'medium_risk'
                        ELSE 'high_risk'
                    END as risk_category,
                    decision,
                    COUNT(*) as count
                FROM zta.trust_decisions
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                GROUP BY risk_category, decision
            """)).mappings().all()

            # Component analysis
            component_stats = conn.execute(text(f"""
                SELECT
                    jsonb_array_elements_text(components::jsonb->'stride') as stride_component,
                    decision,
                    COUNT(*) as count
                FROM zta.trust_decisions
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                AND components::jsonb->'stride' IS NOT NULL
                GROUP BY stride_component, decision
            """)).mappings().all()

            return {
                "decision_distribution": [
                    {
                        "decision": r["decision"],
                        "count": r["count"],
                        "avg_risk": float(r["avg_risk"] or 0),
                        "risk_range": [
                            float(r["min_risk"] or 0),
                            float(r["max_risk"] or 0)
                        ]
                    } for r in decision_dist
                ],
                "risk_decision_correlation": [
                    {
                        "risk_category": r["risk_category"],
                        "decision": r["decision"],
                        "count": r["count"]
                    } for r in risk_decision_correlation
                ],
                "stride_impact": [
                    {
                        "stride_component": r["stride_component"],
                        "decision": r["decision"],
                        "count": r["count"]
                    } for r in component_stats
                ]
            }
    except Exception as e:
        return {"error": str(e)}

@api.on_event("startup")
def _startup():
    """Warm the DB pool before accepting traffic — see validation service for rationale."""
    get_engine()

@api.get("/health")
def health():
    return {"status": "ok", "service": "metrics-collection"}

@api.get("/metrics/comprehensive", response_model=MetricsResponse)
def get_comprehensive_metrics(
    hours: int = Query(24, description="Hours of data to analyze")
):
    """Get comprehensive metrics for the specified time period"""

    security = calculate_security_metrics(hours)
    performance = calculate_performance_metrics(hours)
    detection = calculate_detection_metrics(hours)
    decision = calculate_decision_metrics(hours)

    return MetricsResponse(
        security_metrics=security,
        performance_metrics=performance,
        detection_metrics=detection,
        decision_metrics=decision,
        timestamp=datetime.utcnow().isoformat()
    )

@api.get("/metrics/security")
def get_security_metrics(
    hours: int = Query(24, description="Hours of data to analyze")
):
    """Get security-specific metrics"""
    return calculate_security_metrics(hours)

@api.get("/metrics/performance")
def get_performance_metrics(
    hours: int = Query(24, description="Hours of data to analyze")
):
    """Get performance-specific metrics"""
    return calculate_performance_metrics(hours)

@api.get("/metrics/detection")
def get_detection_metrics(
    hours: int = Query(24, description="Hours of data to analyze")
):
    """Get threat detection accuracy metrics"""
    return calculate_detection_metrics(hours)

@api.get("/metrics/decisions")
def get_decision_metrics(
    hours: int = Query(24, description="Hours of data to analyze")
):
    """Get decision accuracy and effectiveness metrics"""
    return calculate_decision_metrics(hours)

@api.get("/metrics/comparison")
def get_comparison_metrics(
    hours: int = Query(24, description="Hours of data to analyze")
):
    """Get metrics formatted for baseline comparison"""
    eng = get_engine()
    if eng is None:
        return {
            "error": "Database connection unavailable",
            "proposed_framework": {},
            "baseline_framework": {},
            "comparison": {}
        }

    try:
        with eng.connect() as conn:
            # Get framework comparison data
            framework_stats = conn.execute(text(f"""
                SELECT
                    framework_type,
                    COUNT(*) as total_events,
                    COUNT(*) FILTER (WHERE decision = 'allow') as allow_count,
                    COUNT(*) FILTER (WHERE decision = 'step_up') as stepup_count,
                    COUNT(*) FILTER (WHERE decision = 'deny') as deny_count,
                    AVG(risk_score) as avg_risk_score,
                    AVG(processing_time_ms) as avg_processing_time
                FROM zta.framework_comparison
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                GROUP BY framework_type
            """)).mappings().all()

            # Get security classifications
            security_stats = conn.execute(text(f"""
                SELECT
                    framework_type,
                    COUNT(*) as total_classifications,
                    COUNT(*) FILTER (WHERE false_positive = TRUE) as false_positives,
                    COUNT(*) FILTER (WHERE false_negative = TRUE) as false_negatives
                FROM zta.security_classifications
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                GROUP BY framework_type
            """)).mappings().all()

            # Format results by framework
            frameworks = {}
            for stat in framework_stats:
                framework = stat["framework_type"]
                total = stat["total_events"] or 0
                frameworks[framework] = {
                    "total_events": total,
                    "decisions": {
                        "allow": stat["allow_count"] or 0,
                        "step_up": stat["stepup_count"] or 0,
                        "deny": stat["deny_count"] or 0
                    },
                    "success_rate": ((stat["allow_count"] or 0) / max(total, 1)) * 100,
                    "mfa_rate": ((stat["stepup_count"] or 0) / max(total, 1)) * 100,
                    "deny_rate": ((stat["deny_count"] or 0) / max(total, 1)) * 100,
                    "avg_risk_score": float(stat["avg_risk_score"] or 0),
                    "avg_processing_time_ms": float(stat["avg_processing_time"] or 0)
                }

            # Add security classification data
            for stat in security_stats:
                framework = stat["framework_type"]
                if framework in frameworks:
                    total_class = stat["total_classifications"] or 0
                    frameworks[framework]["security_accuracy"] = {
                        "total_classifications": total_class,
                        "false_positives": stat["false_positives"] or 0,
                        "false_negatives": stat["false_negatives"] or 0,
                        "false_positive_rate": ((stat["false_positives"] or 0) / max(total_class, 1)) * 100,
                        "false_negative_rate": ((stat["false_negatives"] or 0) / max(total_class, 1)) * 100
                    }

            return {
                "comparison_period_hours": hours,
                "frameworks": frameworks,
                "comparison": {
                    "frameworks_available": list(frameworks.keys()),
                    "total_comparisons": sum(fw.get("total_events", 0) for fw in frameworks.values()),
                }
            }

    except Exception as e:
        return {
            "error": str(e),
            "frameworks": {},
            "comparison": {}
        }

@api.get("/metrics/export")
def export_metrics(
    hours: int = Query(24, description="Hours of data to analyze"),
    format: str = Query("json", description="Export format")
):
    """Export metrics for external analysis"""

    comprehensive = get_comprehensive_metrics(hours)

    if format.lower() == "csv":
        # For CSV format, we'd flatten the data structure
        # This is a simplified version - you might want to expand this
        return {
            "format": "csv",
            "note": "CSV export would flatten the nested structure",
            "data": comprehensive
        }

    return comprehensive

@api.get("/thesis/security-accuracy")
def get_thesis_security_accuracy(
    hours: int = Query(24, description="Hours of data to analyze")
):
    """Get security accuracy metrics (TPR, FPR, Precision, Recall, F1-Score) for thesis analysis"""
    eng = get_engine()
    if eng is None:
        return {"error": "Database connection unavailable"}

    try:
        calculator = ThesisMetricsCalculator(eng)
        return calculator.calculate_security_accuracy_metrics(hours)
    except Exception as e:
        logger.error(f"Error calculating security accuracy metrics: {e}")
        return {"error": str(e)}

@api.get("/thesis/failed-logins")
def get_thesis_failed_logins(
    hours: int = Query(24, description="Hours of data to analyze")
):
    """Get failed login attempts comparison for thesis analysis"""
    eng = get_engine()
    if eng is None:
        return {"error": "Database connection unavailable"}

    try:
        calculator = ThesisMetricsCalculator(eng)
        return calculator.calculate_failed_login_attempts(hours)
    except Exception as e:
        logger.error(f"Error calculating failed login metrics: {e}")
        return {"error": str(e)}

@api.get("/thesis/performance")
def get_thesis_performance(
    hours: int = Query(24, description="Hours of data to analyze")
):
    """Get comprehensive performance metrics for thesis analysis"""
    eng = get_engine()
    if eng is None:
        return {"error": "Database connection unavailable"}

    try:
        calculator = ThesisMetricsCalculator(eng)
        return calculator.calculate_system_performance_metrics(hours)
    except Exception as e:
        logger.error(f"Error calculating performance metrics: {e}")
        return {"error": str(e)}

@api.get("/thesis/usability")
def get_thesis_usability(
    hours: int = Query(24, description="Hours of data to analyze")
):
    """Get usability metrics for thesis analysis"""
    eng = get_engine()
    if eng is None:
        return {"error": "Database connection unavailable"}

    try:
        calculator = ThesisMetricsCalculator(eng)
        return calculator.calculate_usability_metrics(hours)
    except Exception as e:
        logger.error(f"Error calculating usability metrics: {e}")
        return {"error": str(e)}

@api.get("/thesis/privacy")
def get_thesis_privacy(
    hours: int = Query(24, description="Hours of data to analyze")
):
    """Get privacy preserving metrics for thesis analysis"""
    eng = get_engine()
    if eng is None:
        return {"error": "Database connection unavailable"}

    try:
        calculator = ThesisMetricsCalculator(eng)
        return calculator.calculate_privacy_metrics(hours)
    except Exception as e:
        logger.error(f"Error calculating privacy metrics: {e}")
        return {"error": str(e)}

@api.get("/thesis/comprehensive")
def get_thesis_comprehensive_analysis(
    hours: int = Query(24, description="Hours of data to analyze")
):
    """Get comprehensive thesis metrics analysis including all categories"""
    eng = get_engine()
    if eng is None:
        return {"error": "Database connection unavailable"}

    try:
        calculator = ThesisMetricsCalculator(eng)
        return calculator.generate_comprehensive_comparison(hours)
    except Exception as e:
        logger.error(f"Error generating comprehensive analysis: {e}")
        return {"error": str(e)}

@api.get("/thesis/elasticsearch-export")
def get_thesis_elasticsearch_export(
    hours: int = Query(24, description="Hours of data to analyze")
):
    """Export thesis metrics in Elasticsearch-ready format"""
    eng = get_engine()
    if eng is None:
        return {"error": "Database connection unavailable"}

    try:
        calculator = ThesisMetricsCalculator(eng)
        documents = calculator.export_for_elasticsearch(hours)
        return {
            "documents": documents,
            "count": len(documents),
            "analysis_period_hours": hours,
            "export_timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error exporting for Elasticsearch: {e}")
        return {"error": str(e)}
