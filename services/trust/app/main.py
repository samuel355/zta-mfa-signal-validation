import os, json
from typing import Dict, Any, Optional
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

api = FastAPI(title="Trust Service", version="0.5")

# ---------- Thresholds ----------
ALLOW_T = float(os.getenv("ALLOW_T", "0.25"))
DENY_T  = float(os.getenv("DENY_T", "0.70"))
SIEM_HIGH_BUMP = float(os.getenv("SIEM_HIGH_BUMP", "0.15"))
SIEM_MED_BUMP  = float(os.getenv("SIEM_MED_BUMP", "0.07"))
TRUST_BASE_GAIN = float(os.getenv("TRUST_BASE_GAIN", "0.05"))
TRUST_FALLBACK_OBSERVED = float(os.getenv("TRUST_FALLBACK_OBSERVED", "0.1"))

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
    reasons = [r.upper() for r in (payload.reasons or [])]
    weights = payload.weights or {}
    siem    = payload.siem or {"high": 0, "medium": 0}

    # --- Base risk
    risk = TRUST_BASE_GAIN if weights else TRUST_FALLBACK_OBSERVED

    # --- STRIDE mapping bumps ---
    stride_map = {
        "SPOOFING": ("Spoofing", 0.2),
        "DOS": ("Denial of Service", 0.3),
        "POLICY_ELEVATION": ("Elevation of Privilege", 0.25),
        "DOWNLOAD_EXFIL": ("Information Disclosure", 0.25),
        "TLS_ANOMALY": ("Tampering", 0.2),
        "POSTURE_OUTDATED": ("Tampering", 0.2),
        "REPUDIATION": ("Repudiation", 0.4)
    }
    stride_used = []
    for r in reasons:
        for k, (stride_name, bump) in stride_map.items():
            if r.startswith(k):
                risk += bump
                stride_used.append(stride_name)

    # --- SIEM bumps ---
    risk += siem.get("high", 0) * SIEM_HIGH_BUMP
    risk += siem.get("medium", 0) * SIEM_MED_BUMP

    # normalize
    risk = max(0.0, min(1.0, risk))

    # --- Decision ---
    decision = "allow"
    if risk >= DENY_T:
        decision = "deny"
    elif risk >= ALLOW_T:
        decision = "step_up"

    # --- Persist decision ---
    session_id = payload.vector.get("session_id") or f"sess-{os.urandom(4).hex()}"
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
                            "stride": list(set(stride_used))  # canonical STRIDE labels
                        })
                    }
                )
            persistence = {"ok": True}
            print(f"[TRUST] Inserted decision for {session_id}: {decision} (risk={risk})")
        except Exception as e:
            persistence = {"ok": False, "error": str(e)}
            print(f"[TRUST][DB] Insert failed: {e}")

    return {"risk": round(risk, 2), "decision": decision, "persistence": persistence}