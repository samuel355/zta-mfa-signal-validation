from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any, Optional
import os, urllib.parse, socket, json
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

api = FastAPI(title="Trust Service", version="0.3")

class ValidatedPayload(BaseModel):
    vector: Dict[str, Any] = {}
    weights: Dict[str, float] = {}
    reasons: list[str] = []
    siem: Dict[str, int] = {}

_engine: Optional[Engine] = None

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
        print("[DB] DB_DSN missing; skipping persistence")
        return None
    if dsn.startswith("postgresql://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgresql://"):]
    elif dsn.startswith("postgres://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgres://"):]
    if "sslmode=" not in dsn:
        dsn += ("&" if "?" in dsn else "?") + "sslmode=require"
    try:
        _engine = create_engine(dsn, pool_pre_ping=True, future=True)
        with _engine.connect() as conn:
            conn.execute(text("select 1"))
        print(f"[DB] Engine created OK for {_mask_dsn(dsn)}")
    except Exception as e:
        print(f"[DB] Failed to create engine for {_mask_dsn(dsn)}: {e}")
        _engine = None
    return _engine

# ---- thesis thresholds ----
ALLOW_T = float(os.getenv("ALLOW_T", "0.25"))   # r < 0.25
DENY_T  = float(os.getenv("DENY_T",  "0.75"))   # r >= 0.75
ALPHA   = float(os.getenv("SIEM_HIGH_BUMP", "0.15"))
BETA    = float(os.getenv("SIEM_MED_BUMP",  "0.07"))

# map reasons → signal keys whose weight applies
REASON_TO_SIGNAL = {
    "IP_GEO_MISMATCH": "ip_geo",
    "GPS_MISMATCH": "gps",
    "WIFI_MISMATCH": "wifi_bssid",
    "TLS_ANOMALY": "tls_fp",
    "POSTURE_OUTDATED": "device_posture",
    # informational threat types from CICIDS labels (mapped in validation)
    "BRUTE_FORCE": "ip_geo",
    "POLICY_ELEVATION": "ip_geo",
    "DOWNLOAD_EXFIL": "ip_geo",
}

@api.get("/health")
def health():
    return {"status": "ok"}

@api.post("/score")
def score(payload: ValidatedPayload):
    w = payload.weights or {}
    reasons = payload.reasons or []
    siem = payload.siem or {}

    # base risk = sum of weights for signals implicated by reasons (unique)
    used_signals = set()
    for r in reasons:
        k = REASON_TO_SIGNAL.get(r)
        if k: used_signals.add(k)
    base = float(sum(w.get(k, 0.0) for k in used_signals))

    # siem bump (count-based)
    siem_term = ALPHA * float(siem.get("high", 0) or 0) + BETA * float(siem.get("medium", 0) or 0)

    r = base + siem_term
    # clamp to [0,1]
    if r < 0.0: r = 0.0
    if r > 1.0: r = 1.0

    if r < ALLOW_T:
        decision = "allow"
    elif r < DENY_T:
        decision = "step_up"
    else:
        decision = "deny"

    components = {"base": base, "siem_bump": siem_term, "signals_used": sorted(used_signals)}

    # Persist
    persistence = {"ok": False}
    eng = get_engine()
    if eng is not None:
        try:
            with eng.begin() as conn:
                conn.execute(text("SET LOCAL statement_timeout = '3s'"))
                conn.execute(
                    text("""
                        insert into zta.trust_decisions (session_id, risk, decision, components)
                        values (:session_id, :risk, :decision, cast(:components as jsonb))
                    """),
                    {
                        "session_id": payload.vector.get("session_id") or f"sess-{os.urandom(4).hex()}",
                        "risk": r,
                        "decision": decision,
                        "components": json.dumps(components),
                    }
                )
            persistence = {"ok": True}
        except Exception as ex:
            persistence = {"ok": False, "error": str(ex)}

    return {"risk": r, "decision": decision, "components": components, "persistence": persistence}