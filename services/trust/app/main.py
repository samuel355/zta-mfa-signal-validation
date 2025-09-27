import os, json
from typing import Dict, Any, Optional
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from decision_engine import process_proposed_request, get_proposed_thesis_metrics, reset_proposed_metrics, compare_frameworks

api = FastAPI(title="Trust Service", version="0.5")

# ---------- Thresholds ----------
ALLOW_T = float(os.getenv("ALLOW_T", "0.12"))
DENY_T  = float(os.getenv("DENY_T", "0.80"))
SIEM_HIGH_BUMP = float(os.getenv("SIEM_HIGH_BUMP", "0.18"))
SIEM_MED_BUMP  = float(os.getenv("SIEM_MED_BUMP", "0.08"))
TRUST_BASE_GAIN = float(os.getenv("TRUST_BASE_GAIN", "0.02"))
TRUST_FALLBACK_OBSERVED = float(os.getenv("TRUST_FALLBACK_OBSERVED", "0.05"))

# Thesis-compliant configuration
BENIGN_TRAFFIC_PERCENT = float(os.getenv("BENIGN_TRAFFIC_PERCENT", "70")) / 100
VALIDATION_CONFIDENCE_THRESHOLD = float(os.getenv("VALIDATION_CONFIDENCE_THRESHOLD", "0.70"))

_engine: Optional[Engine] = None

# ---------- Database ----------
def get_engine() -> Optional[Engine]:
    global _engine
    if _engine is not None:
        return _engine
    dsn = os.getenv("DB_DSN", "").strip()
    if not dsn:
        print("[TRUST][DB] No DB_DSN set")
        return None
    if dsn.startswith("postgresql://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgresql://") :]
    elif dsn.startswith("postgres://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgres://") :]
    if "sslmode=" not in dsn:
        dsn += ("&" if "?" in dsn else "?") + "sslmode=require"
    try:
        _engine = create_engine(dsn, pool_pre_ping=True, future=True)
        with _engine.connect() as c:
            c.execute(text("select 1"))
        print("[TRUST][DB] Engine created OK")
    except Exception as e:
        print(f"[TRUST][DB] Failed to init engine: {e}")
        _engine = None
    return _engine

# ---------- Payload ----------
class ScorePayload(BaseModel):
    vector: Dict[str, Any]
    weights: Dict[str, float]
    reasons: list[str] = []
    siem: Dict[str, int] = {}

# ---------- Health ----------
@api.get("/health")
def health():
    return {"status": "ok"}

# ---------- Score ----------
@api.post("/score")
def score(payload: ScorePayload):
    """Score using thesis-compliant proposed framework engine"""
    import time
    decision_start_time = time.perf_counter()

    # Prepare validated context for the thesis engine
    validated_context = {
        'vector': payload.vector,
        'weights': payload.weights or {},
        'reasons': payload.reasons or [],
        'siem': payload.siem or {"high": 0, "medium": 0}
    }

    # Use the thesis-compliant proposed engine
    result = process_proposed_request(validated_context)

    # Extract decision information from the result
    session_id = result.get("session_id", payload.vector.get("session_id", f"sess-{os.urandom(4).hex()}"))
    decision = result.get("decision", "allow")
    risk = result.get("risk_score", 0.0)

    # Extract additional fields from the structured response
    reasons = result.get("details", {}).get("reasons", payload.reasons or [])
    weights = payload.weights or {}
    siem = payload.siem or {}

    # Extract validation metrics
    validation_metrics = result.get("validation_metrics", {})
    confidence_multiplier = validation_metrics.get("overall_confidence", 1.0)

    # Extract details
    details = result.get("details", {})
    is_benign_traffic = details.get("actual_threat_level", "benign") == "benign"

    # Extract STRIDE components (could be in reasons or generated based on risk)
    stride_components = []
    if "spoofing" in str(reasons).lower():
        stride_components.append("Spoofing")
    if "tampering" in str(reasons).lower():
        stride_components.append("Tampering")
    if risk > 0.5:
        stride_components.append("EoP")
    if not stride_components:
        stride_components = ["None"]

    # Calculate decision time
    decision_end_time = time.perf_counter()
    decision_time_ms = result.get("thesis_metrics", {}).get("processing_time_ms",
                                  int((decision_end_time - decision_start_time) * 1000))

    # --- Persist decision ---
    persistence = {"ok": False}
    eng = get_engine()
    if eng is not None:
        try:
            with eng.begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO zta.trust_decisions (session_id, risk, decision, components)
                        VALUES (:sid, :risk, :decision, CAST(:comp AS jsonb))
                    """),
                    {
                        "sid": session_id,
                        "risk": risk,
                        "decision": decision,
                        "comp": json.dumps({
                            "reasons": reasons,
                            "weights": weights,
                            "siem_bump": siem,
                            "stride": stride_components,
                            "decision_time_ms": decision_time_ms,
                            "confidence_multiplier": confidence_multiplier,
                            "is_benign_traffic": is_benign_traffic,
                            "signal_quality": validation_metrics.get("signal_coverage", sum(weights.values()) if weights else 0),
                            "validation_confidence": confidence_multiplier,
                            "enrichment_quality": validation_metrics.get("enrichment_quality_score", 0.8),
                            "context_mismatches": details.get("context_mismatches", 0)
                        })
                    }
                )
            persistence = {"ok": True}
            print(f"[TRUST] {session_id}: {decision} (risk={risk:.3f}, time={decision_time_ms}ms)")
        except Exception as e:
            persistence = {"ok": False, "error": str(e)}
            print(f"[TRUST][DB] Insert failed: {e}")

    # Return response compatible with existing API
    return {
        "risk": round(risk, 3),
        "decision": decision,
        "persistence": persistence,
        "decision_time_ms": decision_time_ms,
        "confidence_score": round(confidence_multiplier, 3),
        "stride_components": stride_components,
        "framework_type": "proposed",
        "validation_applied": True,
        "enrichment_applied": True,
        "thesis_metrics": result.get("thesis_metrics", {}),
        "validation_metrics": validation_metrics
    }

# ---------- Additional Endpoints ----------
@api.get("/metrics")
def get_metrics():
    """Get current thesis metrics for the proposed framework"""
    return get_proposed_thesis_metrics()

@api.post("/reset_metrics")
def reset_metrics():
    """Reset metrics for testing"""
    reset_proposed_metrics()
    return {"status": "metrics_reset", "framework": "proposed"}

@api.get("/compare")
def compare():
    """Compare baseline vs proposed frameworks"""
    return compare_frameworks()
