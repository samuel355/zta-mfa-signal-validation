import os, json, asyncio, datetime as dt, urllib.parse, socket
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
import httpx

api = FastAPI(title="SIEM Connector", version="0.5")

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
        print("[DB] missing DB_DSN"); return None
    if dsn.startswith("postgresql://"): dsn = "postgresql+psycopg://" + dsn[len("postgresql://"):]
    elif dsn.startswith("postgres://"): dsn = "postgresql+psycopg://" + dsn[len("postgres://"):]
    if "sslmode=" not in dsn:
        dsn += ("&" if "?" in dsn else "?") + "sslmode=require"
    try:
        _engine = create_engine(dsn, pool_pre_ping=True, future=True)
        with _engine.connect() as c: c.execute(text("select 1"))
        print(f"[DB] Engine OK for {_mask_dsn(dsn)}")
    except Exception as e:
        print(f"[DB] Engine FAIL: {e}"); _engine=None
    return _engine

# ---------- ES config ----------
ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200").rstrip("/")
ES_USER = os.getenv("ES_USER", "")
ES_PASS = os.getenv("ES_PASS", "")
ES_API_KEY = os.getenv("ES_API_KEY", "")
ES_INDEX = os.getenv("ES_INDEX", "mfa-events*")
ES_SESSION_FIELD = os.getenv("ES_SESSION_FIELD", "session_id")
ES_DEFAULT_STRIDE = os.getenv("ES_DEFAULT_STRIDE", "Tampering")
ES_DEFAULT_SEVERITY = os.getenv("ES_DEFAULT_SEVERITY", "medium")
ES_POLL_SECONDS = int(os.getenv("ES_POLL_SECONDS", "20"))
ES_LOOKBACK = os.getenv("ES_LOOKBACK", "2m")

SEV_HIGH_T = float(os.getenv("SEV_HIGH", "0.75"))
SEV_MED_T  = float(os.getenv("SEV_MED",  "0.25"))

headers = {"content-type": "application/json"}
es_auth = None
if ES_API_KEY:
    headers["Authorization"] = f"ApiKey {ES_API_KEY}"
elif ES_USER and ES_PASS:
    es_auth = httpx.BasicAuth(ES_USER, ES_PASS)

# ---------- Reason → STRIDE ----------
DEFAULT_REASON_TO_STRIDE: Dict[str, str] = {
    "GPS_MISMATCH": "Spoofing",
    "IP_GEO_MISMATCH": "Spoofing",
    "WIFI_MISMATCH": "Spoofing",
    "IMPOSSIBLE_TRAVEL": "Spoofing",
    "TLS_ANOMALY": "Tampering",
    "JA3_SUSPECT": "Tampering",
    "DEVICE_UNHEALTHY": "Tampering",
    "POSTURE_OUTDATED": "Tampering",
    "DDOS": "DoS",
    "DOS": "DoS",
    "PORTSCAN": "DoS",
    "BRUTE_FORCE": "DoS",
    "DOWNLOAD_EXFIL": "InformationDisclosure",
    "POLICY_ELEVATION": "EoP",
}
SEV_ALLOWED = {"low":"low","medium":"medium","high":"high"}

def _to_float(x, default=None):
    try:
        if isinstance(x, (int,float)): return float(x)
        if isinstance(x, str): return float(x.strip())
    except Exception: pass
    return default

def _derive_severity_from(src: Dict[str, Any]) -> str:
    risk = _to_float(src.get("risk") or src.get("risk_score") or src.get("risk_value"))
    if isinstance(risk, float):
        if risk >= SEV_HIGH_T: return "high"
        if risk >= SEV_MED_T:  return "medium"
        return "low"
    decision = str(src.get("decision") or "").upper()
    enforcement = str(src.get("enforcement") or "").upper()
    if decision in {"BLOCK","DENY"}: return "high"
    if "MFA" in enforcement: return "medium"
    return "low"

def _first_reason_token(src: Dict[str, Any]) -> str:
    candidates=[]
    for key in ("reasons","reason_codes","why","notes","reason"):
        v = src.get(key)
        if not v: continue
        if isinstance(v,str): candidates.append(v)
        elif isinstance(v,list): candidates.extend([str(x) for x in v if x is not None])
        elif isinstance(v,dict): candidates.extend([str(x) for x in v.values() if x is not None])
    if not candidates: return ""
    tok = candidates[0].replace("-","_").replace(" ","_").upper()
    return tok

def _derive_stride_from(src: Dict[str, Any]) -> str:
    rs = src.get("reasons")
    def norm(s: str) -> str: return str(s or "").replace("-","_").replace(" ","_").upper()
    if isinstance(rs, list) and rs:
        for r in rs:
            tok = norm(r)
            if tok in DEFAULT_REASON_TO_STRIDE: return DEFAULT_REASON_TO_STRIDE[tok]
    elif isinstance(rs, str) and rs.strip():
        tok = norm(rs)
        if tok in DEFAULT_REASON_TO_STRIDE: return DEFAULT_REASON_TO_STRIDE[tok]
    tok = _first_reason_token(src)
    if tok in DEFAULT_REASON_TO_STRIDE: return DEFAULT_REASON_TO_STRIDE[tok]
    # field heuristics
    if any(src.get(k) for k in ("gps_mismatch","ip_geo_mismatch","wifi_mismatch","impossible_travel")): return "Spoofing"
    if any(src.get(k) for k in ("tls_anomaly","ja3_suspect","device_unhealthy","posture_outdated")): return "Tampering"
    if any(src.get(k) for k in ("exfil","data_leak")): return "InformationDisclosure"
    if src.get("brute_force"): return "DoS"
    return ES_DEFAULT_STRIDE

class IngestEvent(BaseModel):
    session_id: str = Field(..., description="Correlation id for session")
    severity: str = Field(..., description="low|medium|high")
    stride: str = Field(..., description="Spoofing|Tampering|Repudiation|InformationDisclosure|DoS|EoP")
    source: str | None = None
    raw: Dict[str, Any] = {}

def _index_alert_to_es(ev: IngestEvent):
    if not ES_HOST: return
    doc = {"@timestamp": dt.datetime.utcnow().isoformat(),
           "session_id": ev.session_id, "stride": ev.stride, "severity": ev.severity,
           "source": ev.source, "raw": ev.raw}
    try:
        with httpx.Client(timeout=5, headers=headers, auth=es_auth) as c:
            c.post(f"{ES_HOST}/siem-alerts/_doc", json=doc)
    except Exception as e:
        print(f"[ES_INDEX][siem-alerts] failed: {e}")

def _insert_event(ev: IngestEvent):
    eng = get_engine()
    if eng is None: return {"ok": False, "error": "DB not configured"}
    try:
        with eng.begin() as conn:
            conn.execute(
                text("""
                  insert into zta.siem_alerts (session_id, stride, severity, source, raw)
                  select :session_id, :stride, :severity, :source, cast(:raw as jsonb)
                  where not exists (select 1 from zta.siem_alerts where raw->>'_id' = :es_id)
                """),
                {"session_id": ev.session_id, "stride": ev.stride, "severity": ev.severity,
                 "source": ev.source, "raw": json.dumps(ev.raw),
                 "es_id": ev.raw.get("_id") if isinstance(ev.raw, dict) else None}
            )
        _index_alert_to_es(ev)
        return {"ok": True}
    except Exception as ex:
        return {"ok": False, "error": str(ex)}

@api.get("/health")
def health(): return {"status":"ok"}

@api.get("/dbcheck")
def dbcheck(): return {"ok": get_engine() is not None}

@api.post("/ingest")
def ingest(ev: IngestEvent): return _insert_event(ev)

@api.post("/ingest/elastic")
async def ingest_elastic(req: Request):
    payload = await req.json()
    sev = (payload.get("kibana", {}).get("alert", {}).get("severity")
           or payload.get("event", {}).get("severity") or payload.get("severity") or "medium")
    stride = (payload.get("stride") or payload.get("threat", {}).get("technique") or "InformationDisclosure")
    session_id = (payload.get("session_id") or payload.get("related", {}).get("session")
                  or payload.get("user", {}).get("id") or "sess-unknown")
    ev = IngestEvent(session_id=session_id,
                     severity=str(sev).lower() if str(sev).lower() in SEV_ALLOWED else "medium",
                     stride=str(stride),
                     source="elastic", raw=payload)
    return _insert_event(ev)

@api.get("/aggregate")
def aggregate(session_id: str, minutes: int = 15):
    eng = get_engine()
    if eng is None: return {"ok": False, "error": "DB not configured"}
    sql = """
      select
        sum((severity='high')::int)   as high,
        sum((severity='medium')::int) as medium,
        sum((severity='low')::int)    as low
      from zta.siem_alerts
      where session_id = :sid
        and created_at >= now() - (:mins || ' minutes')::interval
    """
    try:
        with eng.connect() as c:
            row = c.execute(text(sql), {"sid": session_id, "mins": minutes}).mappings().first()
        return {"ok": True, "session_id": session_id, "window_min": minutes, "counts": row}
    except Exception as ex:
        return {"ok": False, "error": str(ex)}

# ---------- Poller ----------
async def _poll_once():
    if not ES_HOST or not ES_INDEX: return
    must_filters = [
        {"range": {"@timestamp": {"gte": f"now-{ES_LOOKBACK}", "lte": "now"}}},
        {"bool": {"should": [
            {"terms": {"enforcement.keyword": ["MFA_STEP_UP","DENY","BLOCK"]}},
            {"terms": {"enforcement":         ["MFA_STEP_UP","DENY","BLOCK"]}},
        ], "minimum_should_match": 1}},
    ]
    q = {"size": 200, "sort": [{"@timestamp": {"order": "asc"}}], "query": {"bool": {"filter": must_filters}}}
    async with httpx.AsyncClient(timeout=10, headers=headers, auth=es_auth) as client:
        try:
            r = await client.post(f"{ES_HOST}/{ES_INDEX}/_search", json=q)
            r.raise_for_status()
            hits = r.json().get("hits", {}).get("hits", []) or []
            for h in hits:
                src = h.get("_source", {}) or {}
                sid = src.get(ES_SESSION_FIELD) or (src.get("user", {}) or {}).get("name") or "sess-unknown"
                sev = _derive_severity_from(src) or ES_DEFAULT_SEVERITY
                stride = _derive_stride_from(src) or ES_DEFAULT_STRIDE
                ev = IngestEvent(session_id=str(sid), severity=sev, stride=stride, source=f"es:{ES_INDEX}",
                                 raw={"_id": h.get("_id"), **src})
                _insert_event(ev)
        except Exception as e:
            print(f"[POLL] error: {e}")

async def _poll_loop():
    while True:
        try:
            await _poll_once()
        except Exception as e:
            print(f"[POLL] loop error: {e}")
        await asyncio.sleep(ES_POLL_SECONDS)

@api.post("/poll-now")
async def poll_now():
    try:
        await _poll_once(); return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@api.on_event("startup")
async def _on_start():
    get_engine()
    if ES_HOST:
        asyncio.create_task(_poll_loop())