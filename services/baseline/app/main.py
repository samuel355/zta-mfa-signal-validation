from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any, Optional
import os, json, hashlib, time
from datetime import datetime
import pyotp
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from baseline_engine import process_baseline_request, get_baseline_thesis_metrics, reset_baseline_metrics

api = FastAPI(title="Baseline MFA Service", version="1.0")

_engine: Optional[Engine] = None

# Simple baseline thresholds (fixed for reasonable decision making)
SUSPICIOUS_IP_PREFIXES = ["203.0.113.", "198.51.100.", "vpn", "proxy", "tor"]  # Actually suspicious ranges only
BUSINESS_HOURS_START = 6  # 6 AM
BUSINESS_HOURS_END = 22   # 10 PM (more reasonable business hours)
MAX_FAILED_ATTEMPTS = 3   # Reasonable threshold
DEVICE_TRUST_HOURS = 24 * 7  # 1 week trust period

# Baseline risk factors (balanced for reasonable decisions)
SUSPICIOUS_IP_WEIGHT = float(os.getenv("BASELINE_SUSPICIOUS_IP_WEIGHT", "0.25"))
UNKNOWN_DEVICE_WEIGHT = float(os.getenv("BASELINE_UNKNOWN_DEVICE_WEIGHT", "0.15"))
LOCATION_ANOMALY_WEIGHT = float(os.getenv("BASELINE_LOCATION_ANOMALY_WEIGHT", "0.10"))
OUTSIDE_HOURS_WEIGHT = float(os.getenv("BASELINE_OUTSIDE_HOURS_WEIGHT", "0.08"))
THREAT_WEIGHT = float(os.getenv("BASELINE_THREAT_WEIGHT", "0.20"))

def _index_baseline_to_es(decision: Dict[str, Any], signals: Dict[str, Any]):
    """Index baseline decisions to Elasticsearch for comparison"""
    import httpx
    import datetime as dt

    es_host = os.getenv("ES_HOST", "http://elasticsearch:9200").rstrip("/")
    es_user = os.getenv("ES_USER", "")
    es_pass = os.getenv("ES_PASS", "")
    es_api_key = os.getenv("ES_API_KEY", "")

    if not es_host:
        return

    doc = {
        "@timestamp": dt.datetime.utcnow().isoformat(),
        "framework": "baseline",
        "session_id": decision["session_id"],
        "risk": float(decision["risk_score"]),
        "decision": decision["decision"],
        "enforcement": decision["enforcement"],
        "factors": decision["factors"],
        "processing_time_ms": decision.get("decision_time_ms", 0)
    }

    headers = {"content-type": "application/json"}
    auth = None
    if es_api_key:
        headers["Authorization"] = f"ApiKey {es_api_key}"
    elif es_user and es_pass:
        auth = httpx.BasicAuth(es_user, es_pass)

    try:
        with httpx.Client(timeout=3, headers=headers, auth=auth) as c:
            # Index to both mfa-events and baseline-specific index
            r1 = c.post(f"{es_host}/mfa-events/_doc", json=doc)
            r2 = c.post(f"{es_host}/baseline-decisions/_doc", json=doc)
            print(f"[BASELINE] Indexed to ES: mfa-events({r1.status_code}), baseline-decisions({r2.status_code})")
    except Exception as e:
        print(f"[BASELINE] ES indexing failed: {e}")

class BaselineRequest(BaseModel):
    signals: Dict[str, Any]

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
        print("[BASELINE][DB] DB_DSN missing; skipping persistence")
        return None
    if dsn.startswith("postgresql://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgresql://"):]
    elif dsn.startswith("postgres://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgres://"):]
    if "sslmode=" not in dsn:
        dsn += ("&" if "?" in dsn else "?") + "sslmode=require"
    try:
        _engine = create_engine(dsn, pool_pre_ping=True, future=True)
        with _engine.connect() as c:
            c.execute(text("select 1"))
        print(f"[BASELINE][DB] Engine created OK for {_mask_dsn(dsn)}")
    except Exception as e:
        print(f"[BASELINE][DB] Failed to create engine for {_mask_dsn(dsn)}: {e}")
        _engine = None
    return _engine

def is_suspicious_ip(ip: str) -> bool:
    """Simple IP-based suspicion detection"""
    if not ip:
        return True  # No IP = suspicious

    # Check against suspicious prefixes
    for prefix in SUSPICIOUS_IP_PREFIXES:
        if ip.startswith(prefix):
            return True

    # Check for known bad patterns (simplified)
    if ip.startswith("0.") or ip.startswith("127.") or ip.startswith("169.254."):
        return True

    return False

def is_outside_business_hours() -> bool:
    """Check if current time is outside business hours"""
    now = datetime.now()
    hour = now.hour

    # Outside business hours or weekend
    if hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END:
        return True
    if now.weekday() >= 5:  # Saturday or Sunday
        return True

    return False

def get_device_fingerprint(signals: Dict[str, Any]) -> str:
    """Create simple device fingerprint"""
    device_info = signals.get("device_posture", {})
    ip = signals.get("ip_geo", {}).get("ip", "unknown")

    # Simple fingerprint based on device ID and IP
    fingerprint_data = f"{device_info.get('device_id', 'unknown')}:{ip}"
    return hashlib.md5(fingerprint_data.encode()).hexdigest()

def is_trusted_device(device_fingerprint: str) -> bool:
    """Check if device was recently trusted"""
    eng = get_engine()
    if eng is None:
        return False

    try:
        with eng.connect() as conn:
            result = conn.execute(text(f"""
                SELECT COUNT(*) FROM zta.baseline_trusted_devices
                WHERE device_fingerprint = :fp
                AND created_at > NOW() - INTERVAL '{DEVICE_TRUST_HOURS} HOURS'
                AND trust_status = 'trusted'
            """), {
                "fp": device_fingerprint
            }).scalar()

            return (result or 0) > 0
    except Exception:
        return False

def check_failed_attempts(session_id: str) -> int:
    """Check recent failed attempts for this session/user"""
    eng = get_engine()
    if eng is None:
        return 0

    try:
        with eng.connect() as conn:
            result = conn.execute(text("""
                SELECT COUNT(*) FROM zta.baseline_auth_attempts
                WHERE session_id = :sid
                AND outcome = 'failed'
                AND created_at > NOW() - INTERVAL '1 hour'
            """), {
                "sid": session_id
            }).scalar()

            return result or 0
    except Exception:
        return 0

def detect_simple_threats(signals: Dict[str, Any]) -> list[str]:
    """Simple threat detection based on basic rules"""
    threats = []

    # Check label from CICIDS dataset
    label = str(signals.get("label", "")).upper()
    if label and label != "BENIGN":
        if "DDOS" in label or "DOS" in label:
            threats.append("DOS_ATTACK")
        if "WEB ATTACK" in label or "SQLI" in label:
            threats.append("WEB_ATTACK")
        if "BOT" in label or "INFILTRATION" in label:
            threats.append("MALWARE")
        if "HEARTBLEED" in label:
            threats.append("TLS_VULNERABILITY")

    # Simple geographic check (if GPS and WiFi are very far apart)
    gps = signals.get("gps", {})
    wifi = signals.get("wifi_bssid", {})
    if gps and wifi:
        # This is a very simplified check - in reality you'd need
        # geolocation database
        threats.append("LOCATION_ANOMALY")

    return threats

def make_baseline_decision(signals: Dict[str, Any]) -> Dict[str, Any]:
    """Make MFA decision using thesis-compliant baseline engine"""
    # Use the new thesis-compliant baseline engine
    result = process_baseline_request(signals)

    # Convert thesis response to legacy format for compatibility
    legacy_result = {
        "session_id": result["session_id"],
        "decision": result["decision"],
        "enforcement": result["enforcement"],
        "risk_score": result["risk_score"],
        "factors": result.get("details", {}).get("risk_factors", {}),
        "device_fingerprint": result.get("details", {}).get("device_fingerprint", "unknown"),
        "decision_time_ms": result.get("thesis_metrics", {}).get("processing_time_ms", 120)
    }

    return legacy_result

def store_baseline_decision(decision: Dict[str, Any],
                          original_signals: Dict[str, Any]):
    """Store baseline decision for comparison and index to Elasticsearch"""
    eng = get_engine()
    if eng is None:
        print("[BASELINE] No DB connection, skipping storage")
        return {"ok": False, "error": "No database connection"}

    try:
        with eng.begin() as conn:
            # Store in baseline_decisions table
            conn.execute(text("""
                INSERT INTO zta.baseline_decisions
                (session_id, decision, risk_score, factors,
                 device_fingerprint, original_signals, method)
                VALUES (:sid, :decision, :risk, CAST(:factors AS jsonb),
                        :device, CAST(:signals AS jsonb), 'baseline_mfa')
            """), {
                "sid": decision["session_id"],
                "decision": decision["decision"],
                "risk": decision["risk_score"],
                "factors": json.dumps(decision["factors"]),
                "device": decision["device_fingerprint"],
                "signals": json.dumps(original_signals),
            })

            # Store auth attempt with proper outcome
            if decision["decision"] == "allow":
                outcome = "success"
            elif decision["decision"] == "deny":
                outcome = "failed"
            else:
                outcome = "mfa_required"

            conn.execute(text("""
                INSERT INTO zta.baseline_auth_attempts
                (session_id, outcome, risk_score, factors)
                VALUES (:sid, :outcome, :risk, CAST(:factors AS jsonb))
            """), {
                "sid": decision["session_id"],
                "outcome": outcome,
                "risk": decision["risk_score"],
                "factors": json.dumps(decision["factors"]),
            })

            # Update device trust for successful and step-up auths
            if decision["decision"] in ["allow", "step_up"]:
                conn.execute(text("""
                    INSERT INTO zta.baseline_trusted_devices
                    (device_fingerprint, trust_status, last_seen)
                    VALUES (:device, 'trusted', NOW())
                    ON CONFLICT (device_fingerprint)
                    DO UPDATE SET last_seen = NOW(), trust_status = 'trusted'
                """), {
                    "device": decision["device_fingerprint"]
                })

        # Index to Elasticsearch if decision warrants it
        _index_baseline_to_es(decision, original_signals)

        print(f"[BASELINE] Stored decision for {decision['session_id']}: {decision['decision']} (risk={decision['risk_score']})")
        return {"ok": True}
    except Exception as e:
        print(f"[BASELINE] Storage error: {e}")
        return {"ok": False, "error": str(e)}

# TOTP for MFA simulation
_TOTP_SECRET = os.getenv("TOTP_SECRET", "JBSWY3DPEHPK3PXP")
totp = pyotp.TOTP(_TOTP_SECRET)

@api.get("/health")
def health():
    return {"status": "ok", "service": "baseline-mfa"}

@api.post("/decision")
def baseline_decision(request: BaselineRequest):
    """Make MFA decision using baseline (traditional) logic"""

    decision = make_baseline_decision(request.signals)
    storage_result = store_baseline_decision(decision, request.signals)

    # Add OTP for MFA step-up simulation
    if decision["enforcement"] == "MFA_REQUIRED":
        decision["otp_demo"] = totp.now()

    # Add storage status
    decision["persistence"] = storage_result

    return decision

@api.get("/stats")
def get_baseline_stats(hours: int = 24):
    """Get baseline system statistics"""
    eng = get_engine()
    if eng is None:
        return {"error": "Database connection unavailable"}

    try:
        with eng.connect() as conn:
            # Decision distribution
            decisions = conn.execute(text(f"""
                SELECT decision, COUNT(*) as count, AVG(risk_score) as avg_risk
                FROM zta.baseline_decisions
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                GROUP BY decision
            """)).mappings().all()

            # Top factors
            factors_query = conn.execute(text(f"""
                SELECT
                    jsonb_array_elements_text(factors) as factor,
                    COUNT(*) as count
                FROM zta.baseline_decisions
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                GROUP BY factor
                ORDER BY count DESC
            """)).mappings().all()

            # Auth outcomes
            auth_outcomes = conn.execute(text(f"""
                SELECT outcome, COUNT(*) as count
                FROM zta.baseline_auth_attempts
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                GROUP BY outcome
            """)).mappings().all()

            return {
                "decision_distribution": [
                    {
                        "decision": r["decision"],
                        "count": r["count"],
                        "avg_risk": float(r["avg_risk"] or 0)
                    } for r in decisions
                ],
                "top_factors": [
                    {
                        "factor": r["factor"],
                        "count": r["count"]
                    } for r in factors_query
                ],
                "auth_outcomes": [
                    {
                        "outcome": r["outcome"],
                        "count": r["count"]
                    } for r in auth_outcomes
                ]
            }
    except Exception as e:
        return {"error": str(e)}

@api.get("/comparison")
def get_comparison_data(hours: int = 24):
    """Get data formatted for comparison with advanced ZTA system"""
    eng = get_engine()
    if eng is None:
        return {"error": "Database connection unavailable"}

    try:
        with eng.connect() as conn:
            # Total events and success rate
            total_events = conn.execute(text(f"""
                SELECT COUNT(*) FROM zta.baseline_auth_attempts
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
            """)).scalar() or 0

            successful_auths = conn.execute(text(f"""
                SELECT COUNT(*) FROM zta.baseline_auth_attempts
                WHERE outcome = 'success'
                AND created_at > NOW() - INTERVAL '{hours} HOURS'
            """)).scalar() or 0

            mfa_required = conn.execute(text(f"""
                SELECT COUNT(*) FROM zta.baseline_auth_attempts
                WHERE outcome = 'mfa_required'
                AND created_at > NOW() - INTERVAL '{hours} HOURS'
            """)).scalar() or 0

            # Threat detection (simple)
            threat_detections = conn.execute(text(f"""
                SELECT
                    jsonb_array_elements_text(factors) as threat_type,
                    COUNT(*) as count
                FROM zta.baseline_decisions
                WHERE created_at > NOW() - INTERVAL '{hours} HOURS'
                AND jsonb_array_length(factors) > 0
                GROUP BY threat_type
            """)).mappings().all()

            return {
                "system": "baseline",
                "metrics": {
                    "total_events": total_events,
                    "success_rate": (
                        (successful_auths / max(total_events, 1)) * 100
                    ),
                    "mfa_rate": (
                        (mfa_required / max(total_events, 1)) * 100
                    ),
                    "threat_detections": [
                        {
                            "type": r["threat_type"],
                            "count": r["count"]
                        } for r in threat_detections
                    ]
                }
            }
    except Exception as e:
        return {"error": str(e)}
