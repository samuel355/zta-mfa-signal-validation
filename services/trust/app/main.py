from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any, Optional
import math, os, urllib.parse, socket, json
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

import datetime as dt
import httpx

def _index_trust_to_es(session_id: str, risk: float, decision: str,
                       components: dict, reasons: list[str]) -> None:
    es_url = os.getenv("ES_URL", "").rstrip("/")
    if not es_url:
        return
    doc = {
        "@timestamp": dt.datetime.utcnow().isoformat(),
        "session_id": session_id,
        "risk": risk,
        "decision": decision,
        "components": components or {},
        "reasons": reasons or [],
    }
    try:
        with httpx.Client(timeout=3) as c:
            c.post(f"{es_url}/trust-decisions/_doc", json=doc)
    except Exception as e:
        print(f"[ES][trust-decisions] index failed: {e}")


api = FastAPI(title="Trust Service", version="0.2")

# ---------- Models ----------
class ValidatedPayload(BaseModel):
    vector: Dict[str, Any] = {}
    weights: Dict[str, float]
    siem: Dict[str, int] = {}

# ---------- DB engine (lazy) ----------
_engine: Optional[Engine] = None

# --- DB engine (lazy) ---
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
    """Create a psycopg (v3) engine; enforce sslmode=require."""
    global _engine
    if _engine is not None:
        return _engine

    dsn = os.getenv("DB_DSN", "").strip()
    if not dsn:
        print("[DB] DB_DSN missing; skipping persistence")
        return None

    # Force psycopg v3 driver
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
# ---------- Utils ----------
def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))

# ---------- Endpoints ----------
@api.get("/health")
def health():
    return {"status": "ok"}

@api.get("/dbcheck")
def dbcheck():
    eng = get_engine()
    if eng is None:
        return {"ok": False, "error": "DB_DSN missing or invalid (engine not created)"}
    try:
        with eng.connect() as conn:
            conn.execute(text("select 1"))
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
            return {'ok': False, 'error': 'Invalid hostname'}
        port = parsed.port or 5432
        ip = socket.gethostbyname(host)
        s = socket.create_connection((ip, port), timeout=5)
        s.close()
        return {"ok": True, "host": host, "ip": ip, "port": port}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@api.post("/score")
def score(payload: ValidatedPayload):
    C = payload.weights or {}          # normalized confidences from Validation
    v = payload.vector or {}
    siem = payload.siem or {}

    # stable session_id
    session_id = v.get("session_id") or f"sess-{os.urandom(4).hex()}"

    # sanitize reasons -> list[str]
    raw_reasons = v.get("reasons")
    reasons: list[str] = [str(x) for x in raw_reasons] if isinstance(raw_reasons, list) else []

    # per-signal anomaly bits from reasons
    rbits = {
        "ip_geo":         1.0 if "VPN_OR_TOR" in reasons else 0.0,
        "gps":            1.0 if ("GPS_MISMATCH" in reasons or "IMPOSSIBLE_TRAVEL" in reasons) else 0.0,
        "wifi_bssid":     1.0 if "WIFI_MISMATCH" in reasons else 0.0,
        "device_posture": 1.0 if "POSTURE_OUTDATED" in reasons else 0.0,
        "tls_fp":         1.0 if ("TLS_ANOMALY" in reasons or "JA3_SUSPECT" in reasons) else 0.0,
    }

    # base = Σ (confidence_i × anomaly_bit_i)
    base = 0.0
    for k, w in C.items():
        try:
            base += float(w) * float(rbits.get(k, 0.0))
        except Exception:
            pass

    # small SIEM bump (capped to 0.30 total)
    siem_bump = min(0.30, 0.20 * bool(siem.get("high")) + 0.10 * bool(siem.get("medium")))

    risk = round(max(0.0, min(1.0, base + siem_bump)), 2)

    # Thesis bands
    if risk >= 0.75:
        decision = "deny"
    elif risk >= 0.25:
        decision = "step_up"
    else:
        decision = "allow"

    components = {"base": round(base, 3), "siem_bump": siem_bump}

    # persist to Postgres with real session_id
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
                    {"session_id": session_id, "risk": risk, "decision": decision,
                     "components": json.dumps(components)}
                )
            persistence = {"ok": True}
        except Exception as ex:
            persistence = {"ok": False, "error": str(ex)}

    # mirror to ES
    try:
        _index_trust_to_es(session_id, risk, decision, components, reasons)
    except Exception:
        pass

    return {"risk": risk, "decision": decision, "reasons": reasons,
            "session_id": session_id, "components": components, "persistence": persistence}