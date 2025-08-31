import os
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any

DB_DSN = os.getenv("DB_DSN", "")
_engine: Engine | None = None
def get_engine() -> Engine | None:
  """Lazily create a database engine if it doesn't exist"""
  global _engine
  if _engine is None:
    if not DB_DSN:
      return None
    try:
      #poo_pre_ping avoids state connection; future=True for SA2
      _engine = create_engine(DB_DSN, pool_pre_ping=True, future=True)
    except Exception as e:
      print(f"Failed to create engine: {e}")
      return None
  return _engine

api = FastAPI(title="Validation Service", version="0.1")

class SignalPayload(BaseModel):
    signals: Dict[str, Any]  # {ip_geo: {...}, gps: {...}, wifi_bssid: {...}, device_posture: {...}, tls_fp: {...}}

def quality_checks(s: dict) -> dict:
    # TODO: freshness, schema, auth checks
    return {"ok": True, "detail": {}}

def cross_checks(s: dict) -> dict:
    # TODO: compare gps vs ip vs wifi, tls vs device posture
    return {"ok": True, "detail": {}}

def enrichment(s: dict) -> dict:
    # TODO: vpn/tor lists, leaked creds, malicious tls fp
    return {"ok": True, "detail": {}}

def compute_weights(s: dict, q: dict, x: dict, e: dict) -> dict:
    # starter weights; adjust later by quality and cross-check outcomes
    weights = {"ip_geo": 0.25, "gps": 0.30, "wifi_bssid": 0.20, "device_posture": 0.15, "tls_fp": 0.10}
    return weights

def aggregate(s: dict, w: dict) -> dict:
    # build validated vector (placeholder)
    return {"vector": s, "weights": w}

@api.get("/health")
def health():
    return {"status": "ok"}

@api.post("/validate")
@api.post("/validate")
def validate(payload: SignalPayload):
    q = quality_checks(payload.signals)
    x = cross_checks(payload.signals)
    e = enrichment(payload.signals)
    w = compute_weights(payload.signals, q, x, e)
    v = aggregate(payload.signals, w)

    persistence_info = {"ok": False}

    # === Persist to Supabase (zta.validated_context) ===
    eng = get_engine()
    if eng is not None:
        try:
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
                    {
                        "session_id": f"sess-{os.urandom(4).hex()}",
                        "signals": payload.signals,
                        "weights": w,
                        "quality": q,
                        "cross_checks": x,
                        "enrichment": e,
                    }
                )
            persistence_info = {"ok": True}
        except Exception as ex:
            # Don't crash; report persistence error
            persistence_info = {"ok": False, "error": str(ex)}

    # ALWAYS return a body
    return {
        "validated": v,
        "quality": q,
        "cross": x,
        "enrichment": e,
        "persistence": persistence_info
    }


