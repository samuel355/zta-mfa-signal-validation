from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any, Optional
import os, json
import httpx
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from app.enrichment import enrich_all, DATA_STATUS

api = FastAPI(title="Validation Service", version="0.4")

class SignalPayload(BaseModel):
    signals: Dict[str, Any]

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
        with _engine.connect() as c: c.execute(text("select 1"))
        print(f"[DB] Engine created OK for {_mask_dsn(dsn)}")
    except Exception as e:
        print(f"[DB] Failed to create engine for {_mask_dsn(dsn)}: {e}")
        _engine = None
    return _engine

CRIT_TLS = {s.strip().lower() for s in (os.getenv("TLS_CRITICAL_TAGS","").split(",") if os.getenv("TLS_CRITICAL_TAGS") else [])}
if not CRIT_TLS:
    CRIT_TLS = {"tor_suspect","malware_family_x","scanner_tool","cloud_proxy","old_openssl","insecure_client","honeypot_fingerprint"}

def compute_reasons(signals: Dict[str, Any], enr: Dict[str, Any]) -> list[str]:
    R: list[str] = []

    # STRIDE via CICIDS
    L = str(signals.get("label") or "").upper()
    if L and L != "BENIGN":
        if "DDOS" in L or L.startswith("DOS") or "PORTSCAN" in L:
            R.append("DOS")                      # Denial of Service
        if "WEB ATTACK" in L or "SQLI" in L or "XSS" in L:
            R.append("POLICY_ELEVATION")         # Elevation of Privilege
        if "BOT" in L or "INFILTRATION" in L:
            R.append("DOWNLOAD_EXFIL")           # Information Disclosure
        if "HEARTBLEED" in L:
            R.append("TLS_ANOMALY")              # Tampering

    # Spoofing (GPS vs Wi-Fi/IP distance)
    dist = ((enr.get("checks") or {}).get("ip_wifi_distance_km"))
    try:
        if isinstance(dist, (int, float)) and dist > 50.0:
            R.extend(["GPS_MISMATCH","WIFI_MISMATCH"])
    except Exception: pass

    # Tampering via TLS / posture
    tag = ((enr.get("tls") or {}).get("tag") or "").strip().lower()
    if tag and tag in CRIT_TLS:
        R.append("TLS_ANOMALY")

    dev = (enr.get("device") or {})
    sim_dev = (signals.get("device_posture") or {})
    patched = sim_dev.get("patched", dev.get("patched"))
    if isinstance(patched, bool) and not patched:
        R.append("POSTURE_OUTDATED")

    # Repudiation flag (simulator sets it)
    if signals.get("repudiation") is True:
        R.append("REPUDIATION")

    # dedupe keep order
    out, seen = [], set()
    for r in R:
        if r and r not in seen: out.append(r); seen.add(r)
    return out

def quality_checks(signals: Dict[str, Any]) -> dict:
    missing = [k for k in ("ip_geo","gps","wifi_bssid","device_posture","tls_fp") if k not in signals]
    return {"ok": True, "missing": missing}

def cross_checks(enr: Dict[str, Any]) -> dict:
    dist = (enr.get("checks") or {}).get("ip_wifi_distance_km")
    return {"ok": True, "gps_wifi_far": bool(isinstance(dist, (int,float)) and dist > 50.0)}

def compute_weights(signals: Dict[str, Any], q: dict, x: dict, e: dict) -> Dict[str, float]:
    present = [k for k in ("ip_geo","gps","wifi_bssid","device_posture","tls_fp") if k in signals]
    if not present: return {}
    base = {k: 1.0 for k in present}
    for k in q.get("missing", []):
        if k in base: base[k] *= 0.3
    if x.get("gps_wifi_far"):
        for k in ("gps","wifi_bssid"):
            if k in base: base[k] *= 0.5
    if isinstance((e.get("tls") or {}).get("tag"), str) and ((e["tls"]["tag"] or "").strip().lower() in CRIT_TLS):
        if "tls_fp" in base: base["tls_fp"] *= 0.2
    s = sum(base.values())
    return {k: v/s for k,v in base.items()} if s>0 else {}

def aggregate(signals: dict, w: dict, reasons: list[str]) -> dict:
    # also include a helper set of which signals appeared (for debug in DB)
    return {"vector": signals, "weights": w, "reasons": reasons, "signals_observed": sorted(list({*signals.keys()}))}

@api.get("/datasets")
def datasets(): return {"loaded": DATA_STATUS}

@api.get("/health")
def health(): return {"status":"ok"}

@api.post("/validate")
def validate(payload: SignalPayload):
    e = enrich_all(payload.signals)
    q = quality_checks(payload.signals)
    x = cross_checks(e)
    reasons = compute_reasons(payload.signals, e)
    w = compute_weights(payload.signals, q, x, e)
    v = aggregate(payload.signals, w, reasons)

    persistence = {"ok": False}
    eng = get_engine()
    if eng is not None:
        try:
            with eng.begin() as conn:
                conn.execute(text("""
                    insert into zta.validated_context
                      (session_id, signals, weights, quality, cross_checks, enrichment)
                    values
                      (:session_id, cast(:signals as jsonb), cast(:weights as jsonb),
                       cast(:quality as jsonb), cast(:cross as jsonb), cast(:enrichment as jsonb))
                """), {
                    "session_id": v["vector"].get("session_id") or f"sess-{os.urandom(4).hex()}",
                    "signals": json.dumps(payload.signals),
                    "weights": json.dumps(w),
                    "quality": json.dumps(q),
                    "cross": json.dumps(x),
                    "enrichment": json.dumps(e),
                })
            persistence={"ok": True}
        except Exception as ex:
            persistence={"ok": False, "error": str(ex)}
        
        # --- Send validated context to Elasticsearch ---
        try:
            from datetime import datetime
            es_host = os.getenv("ES_HOST", "http://elasticsearch:9200").rstrip("/")
            es_user = os.getenv("ES_USER", "")
            es_pass = os.getenv("ES_PASS", "")
            es_api_key = os.getenv("ES_API_KEY", "")
            es_index = os.getenv("ES_VALIDATED_INDEX", "validated-context")
    
            doc = {
                "@timestamp": datetime.utcnow().isoformat(),
                "session_id": v["vector"].get("session_id"),
                "signals": payload.signals,
                "weights": w,
                "quality": q,
                "cross_checks": x,
                "enrichment": e,
                "reasons": reasons,
            }
    
            headers = {"content-type": "application/json"}
            auth = None
            if es_api_key:
                headers["Authorization"] = f"ApiKey {es_api_key}"
            elif es_user and es_pass:
                auth = httpx.BasicAuth(es_user, es_pass)
    
            with httpx.Client(timeout=5, headers=headers, auth=auth) as c:
                r = c.post(f"{es_host}/{es_index}/_doc", json=doc)
                r.raise_for_status()
                print(f"[VALIDATION] Indexed validated context into {es_index}")
        except Exception as ex:
            print(f"[VALIDATION] Failed to index validated context: {ex}")
                
      
    return {"validated": v, "quality": q, "cross": x, "enrichment": e, "persistence": persistence}
