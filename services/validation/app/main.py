from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any, Optional
import os, urllib.parse, socket, json
from app.enrichment import enrich_all, DATA_STATUS
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

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
                user, _pwd = creds.split(':', 1)
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
        with _engine.connect() as c: c.execute(text("select 1"))
        print(f"[DB] Engine created OK for {_mask_dsn(dsn)}")
    except Exception as e:
        print(f"[DB] Failed to create engine for {_mask_dsn(dsn)}: {e}"); _engine = None
    return _engine

# ---------------- dataset-driven checks ----------------

def compute_reasons(signals: Dict[str, Any], enr: Dict[str, Any]) -> list[str]:
    reasons: list[str] = []

    # CICIDS label → explicit reasons
    label_raw = signals.get("label")
    if isinstance(label_raw, str):
        L = label_raw.strip().upper()
        if L != "BENIGN":
            if "DDOS" in L or L.startswith("DOS") or "PORTSCAN" in L:
                reasons.append("DDOS" if "DDOS" in L else "DOS")
            if "WEB ATTACK" in L or "SQLI" in L or "XSS" in L:
                reasons.append("POLICY_ELEVATION")      # → EoP
            if "BOT" in L or "INFILTRATION" in L:
                reasons.append("DOWNLOAD_EXFIL")        # → InfoDisclosure
            if "HEARTBLEED" in L:
                reasons.append("TLS_ANOMALY")

    # Wi-Fi/IP vs GPS distance → Spoofing
    dist = ((enr.get("checks") or {}).get("ip_wifi_distance_km"))
    try:
        if isinstance(dist, (int, float)) and dist > 50.0:
            reasons += ["GPS_MISMATCH","WIFI_MISMATCH"]
    except Exception:
        pass

    # TLS tag (critical only) → Tampering
    # TLS tag  (only treat clearly malicious tags as anomalies)
    crit_env = os.getenv("TLS_CRITICAL_TAGS", "")
    CRITICAL_TLS_TAGS = {s.strip().lower() for s in crit_env.split(",") if s.strip()}

    tag = (enr.get("tls") or {}).get("tag")
    if isinstance(tag, str) and tag.strip().lower() in CRITICAL_TLS_TAGS:
        reasons.append("TLS_ANOMALY")

    # Device posture → Tampering
    dev = (enr.get("device") or {})
    sim_dev = (signals.get("device_posture") or {})
    patched = sim_dev.get("patched", dev.get("patched"))
    if isinstance(patched, bool) and not patched:
        reasons.append("POSTURE_OUTDATED")

    seen=set(); out=[]
    for r in reasons:
        if r and r not in seen:
            out.append(r); seen.add(r)
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
    if isinstance((e.get("tls") or {}).get("tag"), str) and (e["tls"]["tag"].strip().lower() in {
        "known_vpn","tor_suspect","malware_family_x","scanner_tool",
        "cloud_proxy","old_openssl","insecure_client","honeypot_fingerprint"
    }):
        if "tls_fp" in base: base["tls_fp"] *= 0.2
    s = sum(base.values())
    return {k: (v / s) for k, v in base.items()} if s > 0 else {}

def aggregate(signals: dict, w: dict, reasons: list[str]) -> dict:
    return {"vector": signals, "weights": w, "reasons": reasons}

@api.get("/datasets")
def datasets(): return {"loaded": DATA_STATUS}

@api.get("/health")
def health(): return {"status": "ok"}

@api.get("/dbcheck")
def dbcheck():
    eng = get_engine()
    if eng is None: return {"ok": False, "error": "DB_DSN missing or invalid (engine not created)"}
    try:
        with eng.connect() as conn: conn.execute(text("select 1")); return {"ok": True}
    except Exception as ex: return {"ok": False, "error": str(ex)}

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
            params = {
                "session_id": v["vector"].get("session_id") or f"sess-{os.urandom(4).hex()}",
                "signals": json.dumps(payload.signals),
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
                          (:session_id, cast(:signals as jsonb), cast(:weights as jsonb),
                           cast(:quality as jsonb), cast(:cross_checks as jsonb), cast(:enrichment as jsonb))
                    """),
                    params
                )
            persistence = {"ok": True}
        except Exception as ex:
            persistence = {"ok": False, "error": str(ex)}

    return {"validated": v, "quality": q, "cross": x, "enrichment": e, "persistence": persistence}