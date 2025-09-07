from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any, Optional
import os, json
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

api = FastAPI(title="Trust Service", version="0.4")

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
    if _engine is not None: return _engine
    dsn = os.getenv("DB_DSN","").strip()
    if not dsn:
        print("[DB] DB_DSN missing; skipping persistence"); return None
    if dsn.startswith("postgresql://"): dsn = "postgresql+psycopg://" + dsn[len("postgresql://"):]
    elif dsn.startswith("postgres://"): dsn = "postgresql+psycopg://" + dsn[len("postgres://"):]
    if "sslmode=" not in dsn:
        dsn += ("&" if "?" in dsn else "?") + "sslmode=require"
    try:
        _engine = create_engine(dsn, pool_pre_ping=True, future=True)
        with _engine.connect() as conn: conn.execute(text("select 1"))
        print(f"[DB] Engine created OK for {_mask_dsn(dsn)}")
    except Exception as e:
        print(f"[DB] Failed to create engine for {_mask_dsn(dsn)}: {e}"); _engine = None
    return _engine

ALLOW_T = float(os.getenv("ALLOW_T","0.25"))
DENY_T  = float(os.getenv("DENY_T", "0.70"))
ALPHA   = float(os.getenv("SIEM_HIGH_BUMP","0.15"))
BETA    = float(os.getenv("SIEM_MED_BUMP", "0.07"))
TRUST_BASE_GAIN = float(os.getenv("TRUST_BASE_GAIN","1.0"))
FALLBACK_TOP_OBSERVED = os.getenv("TRUST_FALLBACK_OBSERVED","false").lower() in {"1","true","yes","on"}

REASON_TO_SIGNAL = {
    "IP_GEO_MISMATCH": "ip_geo",
    "GPS_MISMATCH": "gps",
    "WIFI_MISMATCH": "wifi_bssid",
    "TLS_ANOMALY": "tls_fp",
    "POSTURE_OUTDATED": "device_posture",

    # CICIDS-derived buckets
    "BRUTE_FORCE": "ip_geo",         # DoS/PortScan
    "POLICY_ELEVATION": "ip_geo",    # web attacks
    "DOWNLOAD_EXFIL": "ip_geo",

    # loose aliases (won't be emitted now, but safe if they appear)
    "DOS": "ip_geo",
    "EOP": "ip_geo",
    "INFO_DISCLOSURE": "ip_geo",
}

@api.get("/health")
def health(): return {"status": "ok"}

@api.post("/score")
def score(payload: ValidatedPayload):
    reasons = payload.reasons or []
    used_signals = {REASON_TO_SIGNAL[r] for r in reasons if r in REASON_TO_SIGNAL}
    observed_signals = sorted([k for k,v in (payload.weights or {}).items() if v > 0])

    base_raw = float(sum((payload.weights or {}).get(k, 0.0) for k in used_signals))
    base = base_raw * TRUST_BASE_GAIN

    if not used_signals and FALLBACK_TOP_OBSERVED and observed_signals:
        top = max((observed_signals), key=lambda k: (payload.weights or {}).get(k, 0.0))
        used_signals.add(top)
        base = ((payload.weights or {}).get(top, 0.0)) * TRUST_BASE_GAIN

    siem_term = ALPHA * float((payload.siem or {}).get("high", 0) or 0) + \
                BETA  * float((payload.siem or {}).get("medium", 0) or 0)

    r = base + siem_term
    r = 0.0 if r < 0 else (1.0 if r > 1 else r)

    decision = "allow" if r < ALLOW_T else ("step_up" if r < DENY_T else "deny")

    components = {
        "base": round(base,3), "siem_bump": round(siem_term,3),
        "signals_used": sorted(used_signals), "signals_observed": observed_signals,
    }

    persistence = {"ok": False}
    eng = get_engine()
    if eng is not None:
        try:
            with eng.begin() as conn:
                conn.execute(text("SET LOCAL statement_timeout = '3s'"))
                conn.execute(
                    text("""
                        insert into zta.trust_decisions (session_id, risk, decision, components)
                        values (:sid, :r, :d, cast(:c as jsonb))
                    """),
                    {
                        "sid": payload.vector.get("session_id") or f"sess-{os.urandom(4).hex()}",
                        "r": r, "d": decision, "c": json.dumps(components),
                    }
                )
            persistence = {"ok": True}
        except Exception as ex:
            persistence = {"ok": False, "error": str(ex)}

    return {"risk": r, "decision": decision, "components": components, "persistence": persistence}