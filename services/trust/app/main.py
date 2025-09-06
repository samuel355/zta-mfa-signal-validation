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
# map reasons → signal keys whose weight applies
REASON_TO_SIGNAL = {
    "IP_GEO_MISMATCH": "ip_geo",
    "IMPOSSIBLE_TRAVEL": "ip_geo",
    "GPS_MISMATCH": "gps",
    "WIFI_MISMATCH": "wifi_bssid",
    "TLS_ANOMALY": "tls_fp",
    "JA3_SUSPECT": "tls_fp",
    "POSTURE_OUTDATED": "device_posture",
    "DEVICE_UNHEALTHY": "device_posture",
    # informational threat types from CICIDS labels (mapped in validation)
    "BRUTE_FORCE": "ip_geo",
    "POLICY_ELEVATION": "ip_geo",
    "DOWNLOAD_EXFIL": "ip_geo",
}

def _signals_from_reasons(reasons: list[str]) -> set[str]:
    used = set()
    for r in reasons or []:
        r = (r or "").strip().upper()
        k = REASON_TO_SIGNAL.get(r)
        if k:
            used.add(k)
        else:
            # safe fallback: map unknown *_MISMATCH into ip_geo; *_TLS into tls_fp; *_DEVICE into device_posture
            if r.endswith("_MISMATCH"):
                used.add("ip_geo")
            elif "TLS" in r or "JA3" in r:
                used.add("tls_fp")
            elif "DEVICE" in r or "POSTURE" in r:
                used.add("device_posture")
    return used

@api.get("/health")
def health():
    return {"status": "ok"}


@api.get("/dbcheck")
def dbcheck():
    eng = get_engine()
    if eng is None:
        return {"ok": False, "error": "DB_DSN missing or invalid (engine not created)"}
    try:
        with eng.connect() as c:
            c.execute(text("select 1"))
        return {"ok": True}
    except Exception as ex:
        return {"ok": False, "error": str(ex)}

@api.get("/dnscheck")
def dnscheck():
    dsn = os.getenv("DB_DSN", "")
    if not dsn:
        return {"ok": False, "error": "DB_DSN not set"}
    try:
        parsed = urllib.parse.urlparse(dsn.replace("postgresql+psycopg", "postgresql"))
        host = parsed.hostname
        if host is None:
            return {"ok": False, "error": "No hostname found in DB_DSN"}
        port = parsed.port or 5432
        ip = socket.gethostbyname(host)
        with socket.create_connection((ip, port), timeout=5):
            pass
        return {"ok": True, "host": host, "ip": ip, "port": port}
    except Exception as e:
        return {"ok": False, "error": str(e)}
        
        
@api.post("/score")
def score(payload: ValidatedPayload):
    w = payload.weights or {}
    reasons = payload.reasons or []
    siem = payload.siem or {}

    # Signals implicated by reasons (risk drivers)
    used_signals = set()
    for r in reasons:
        k = REASON_TO_SIGNAL.get(r)
        if k:
            used_signals.add(k)

    # Base risk only from implicated signals
    base = float(sum(w.get(k, 0.0) for k in used_signals))

    # SIEM bump
    siem_term = ALPHA * float(siem.get("high", 0) or 0) + BETA * float(siem.get("medium", 0) or 0)

    r = base + siem_term
    r = 0.0 if r < 0 else (1.0 if r > 1 else r)

    if r < ALLOW_T:
        decision = "allow"
    elif r < DENY_T:
        decision = "step_up"
    else:
        decision = "deny"

    # Visibility: which signals are present vs. implicated
    observed_signals = sorted([k for k, v in (w or {}).items() if v > 0])
    components = {
        "base": base,
        "siem_bump": siem_term,
        "signals_used": sorted(used_signals),   # implicated by reasons (risk)
        "signals_observed": observed_signals,   # present in the vector (visibility)
    }

    # Persist (unchanged)
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