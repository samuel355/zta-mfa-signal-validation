from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any, Optional
import os, socket, urllib.parse
import json
from app.enrichment import enrich_all, DATA_STATUS
import datetime as dt
import httpx

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

api = FastAPI(title="Validation Service", version="0.2")

def _index_validation_to_es(session_id: str, signals: dict, confidences: dict, reasons: list,
                            quality: dict, cross: dict, enrichment: dict) -> None:
    es_url = os.getenv("ES_URL", "").rstrip("/")
    if not es_url:
        return
    # keep the doc compact & privacy-safe
    sig = signals or {}
    doc = {
        "@timestamp": dt.datetime.utcnow().isoformat(),
        "session_id": session_id,
        "confidences": confidences or {},
        "reasons": reasons or [],
        "quality": (quality or {}).get("detail"),
        "cross": (cross or {}).get("detail"),
        "checks": (enrichment or {}).get("checks"),
        "tls_tag": ((enrichment or {}).get("tls") or {}).get("tag"),
        "device_patched": ((enrichment or {}).get("device") or {}).get("patched"),
        # minimal signal fields helpful for debugging
        "ip": ((sig.get("ip_geo") or {}).get("ip")),
        "gps": {"lat": (sig.get("gps") or {}).get("lat"),
                "lon": (sig.get("gps") or {}).get("lon")},
        "bssid": ((sig.get("wifi_bssid") or {}).get("bssid")),
        "device_id": ((sig.get("device_posture") or {}).get("device_id")),
        "ja3": ((sig.get("tls_fp") or {}).get("ja3")),
    }
    try:
        with httpx.Client(timeout=3) as c:
            c.post(f"{es_url}/validated-context/_doc", json=doc)
    except Exception as e:
        print(f"[ES][validated-context] index failed: {e}")
        
        
# ---------- Models ----------
class SignalPayload(BaseModel):
    signals: Dict[str, Any]

# ---------- DB engine (lazy) ----------
_engine: Optional[Engine] = None

def _mask_dsn(dsn: str) -> str:
    try:
        at = dsn.find('@')
        if '://' in dsn and at != -1:
            head, tail = dsn.split('://', 1)
            creds, rest = tail.split('@', 1)
            if ':' in creds:
                user, _pwd = creds.split(':', 1)
                return f"{head}://{user}:***@{rest}"
    except Exception:
        pass
    return dsn

def get_engine() -> Optional[Engine]:
    """Lazily create the SQLAlchemy engine; return None if DSN missing/invalid."""
    global _engine
    if _engine is not None:
        return _engine

    dsn = os.getenv("DB_DSN", "").strip()       # <-- READ THE ENV VAR *DB_DSN*
    if not dsn:
        print("[DB] DB_DSN missing; skipping persistence")
        return None

    # Normalize and enforce SSL
    if dsn.startswith("postgres://"):
        dsn = "postgresql://" + dsn[len("postgres://"):]
    if "sslmode=" not in dsn:
        dsn += ("&" if "?" in dsn else "?") + "sslmode=require"

    try:
        _engine = create_engine(dsn, pool_pre_ping=True, future=True)
        with _engine.connect() as conn:
            conn.execute(text("select 1"))
        print(f"[DB] Engine created OK for { _mask_dsn(dsn) }")
    except Exception as e:
        print(f"[DB] Failed to create engine for { _mask_dsn(dsn) }: {e}")
        _engine = None
    return _engine

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

# ---------- Helpers (toy logic placeholders) ----------
def quality_checks(s: dict) -> dict:
    return {"ok": True, "detail": {}}

def cross_checks(s: dict) -> dict:
    return {"ok": True, "detail": {}}

def enrichment(s: dict) -> dict:
    return enrich_all(s)

def compute_weights(s: dict, q: dict, x: dict, e: dict) -> dict:
    return {"ip_geo": 0.25, "gps": 0.30, "wifi_bssid": 0.20, "device_posture": 0.15, "tls_fp": 0.10}

def aggregate(s: dict, w: dict) -> dict:
    return {"vector": s, "weights": w}

# ---------- Endpoints ----------
@api.get("/datasets")
def datasets():
    return {"loaded": DATA_STATUS}
    
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

@api.post("/validate")
def validate(payload: SignalPayload):
    # --- keep/propagate session_id for correlation ---
    signals = dict(payload.signals or {})
    session_id = signals.get("session_id") or f"sess-{os.urandom(4).hex()}"
    signals["session_id"] = session_id

    # --- run your current pipeline ---
    q = quality_checks(signals)
    e = enrichment(signals)
    x = cross_checks(signals)         # (your current signature uses just signals)
    w = compute_weights(signals, q, x, e)
    v = aggregate(signals, w)

    # --- persist to Postgres (unchanged except session_id) ---
    persistence_info = {"ok": False}
    eng = get_engine()
    if eng is not None:
        try:
            params = {
              "session_id": session_id,
              "signals": json.dumps(signals),
              "weights": json.dumps(w),
              "quality": json.dumps(q),
              "cross_checks": json.dumps(x),
              "enrichment": json.dumps(e),
            }
            with eng.begin() as conn:
                conn.execute(
                    text("""
                        insert into zta.validated_context
                          (session_id, signals, weights, quality, cross_checks, enrichment)
                        values
                          (:session_id,
                           cast(:signals as jsonb),
                           cast(:weights as jsonb),
                           cast(:quality as jsonb),
                           cast(:cross_checks as jsonb),
                           cast(:enrichment as jsonb))
                    """),
                    params
                )
            persistence_info = {"ok": True}
        except Exception as ex:
            persistence_info = {"ok": False, "error": str(ex)}

    # --- mirror to Elasticsearch for Kibana ---
    try:
        # reasons not computed yet in your current code; empty list is fine
        _index_validation_to_es(session_id, signals, w, [], q, x, e)
    except Exception:
        pass

    return {
        "validated": v,
        "quality": q,
        "cross": x,
        "enrichment": e,
        "persistence": persistence_info
    }