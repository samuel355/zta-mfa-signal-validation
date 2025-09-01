import os, json, urllib.parse, socket
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

api = FastAPI(title="SIEM Connector", version="0.2")

# ---- DB engine ----
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
        print("[DB] missing DB_DSN"); return None
    if dsn.startswith("postgresql://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgresql://"):]
    elif dsn.startswith("postgres://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgres://"):]
    if "sslmode=" not in dsn:
        dsn += ("&" if "?" in dsn else "?") + "sslmode=require"
    try:
        _engine = create_engine(dsn, pool_pre_ping=True, future=True)
        with _engine.connect() as c: c.execute(text("select 1"))
        print(f"[DB] Engine OK for {_mask_dsn(dsn)}")
    except Exception as e:
        print(f"[DB] Engine FAIL: {e}"); _engine = None
    return _engine

# ---- Models / normalizers ----
STRIDE_ALLOWED = {"spoofing":"Spoofing","tampering":"Tampering","repudiation":"Repudiation",
                  "informationdisclosure":"InformationDisclosure","dos":"DoS","eop":"EoP"}
SEV_ALLOWED = {"low":"low","medium":"medium","high":"high","critical":"high"}  # map critical→high to satisfy CHECK

class IngestEvent(BaseModel):
    session_id: str = Field(..., description="Correlation id for session")
    severity: str = Field(..., description="low|medium|high (critical→high)")
    stride: str = Field(..., description="Spoofing|Tampering|Repudiation|InformationDisclosure|DoS|EoP")
    source: str | None = None
    raw: Dict[str, Any] = {}

def _upcase_stride(s: str) -> str:
    k = (s or "").replace("_","").replace("-","").replace(" ","").lower()
    return STRIDE_ALLOWED.get(k, "InformationDisclosure")  # safe default

def _norm_sev(s: str) -> str:
    k = (s or "").lower()
    return SEV_ALLOWED.get(k, "medium")

def _insert_event(ev: IngestEvent):
    eng = get_engine()
    if eng is None: return {"ok": False, "error": "DB not configured"}
    try:
        with eng.begin() as conn:
            conn.execute(
                text("""
                    insert into zta.siem_alerts (session_id, stride, severity, source, raw)
                    values (:session_id, :stride, :severity, :source, cast(:raw as jsonb))
                """),
                {
                    "session_id": ev.session_id,
                    "stride": _upcase_stride(ev.stride),
                    "severity": _norm_sev(ev.severity),
                    "source": ev.source,
                    "raw": json.dumps(ev.raw),
                }
            )
        return {"ok": True}
    except Exception as ex:
        return {"ok": False, "error": str(ex)}

# ---- Health/diag ----
@api.get("/health")
def health(): return {"status": "ok"}

@api.get("/dbcheck")
def dbcheck():
    return {"ok": get_engine() is not None}

@api.get("/dnscheck")
def dnscheck():
    dsn = os.getenv("DB_DSN", "")
    if not dsn: return {"ok": False, "error": "DB_DSN not set"}
    try:
        parsed = urllib.parse.urlparse(dsn.replace("postgresql+psycopg", "postgresql"))
        host = parsed.hostname
        if host is None: return {"ok": False, "error": "No hostname in DB_DSN"}
        ip = socket.gethostbyname(host)
        return {"ok": True, "host": host, "ip": ip}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ---- Generic ingest (already normalized) ----
@api.post("/ingest")
def ingest(ev: IngestEvent):
    return _insert_event(ev)

# ---- Elastic-specific (Kibana Webhook) ----
@api.post("/ingest/elastic")
async def ingest_elastic(req: Request):
    payload = await req.json()
    # try to derive fields from common Elastic alert schema
    rule = (payload.get("rule", {}) or {})
    sev = (payload.get("kibana", {}).get("alert", {}).get("severity")
           or payload.get("event", {}).get("severity") or payload.get("severity") or "medium")
    stride = (payload.get("stride") or payload.get("threat",{}).get("technique") or "InformationDisclosure")
    session_id = (payload.get("session_id") or payload.get("related",{}).get("session") or payload.get("user",{}).get("id"))
    if not session_id:
        # allow explicit override via query string ?session_id=... if your rule can’t provide it
        session_id = req.query_params.get("session_id", "sess-unknown")

    ev = IngestEvent(
        session_id=session_id,
        severity=_norm_sev(str(sev)),
        stride=_upcase_stride(str(stride)),
        source="elastic",
        raw=payload
    )
    return _insert_event(ev)

# ---- Aggregate for trust model input ----
@api.get("/aggregate")
def aggregate(session_id: str, minutes: int = 15):
    """
    Return severity counts in trailing window for a given session_id.
    Maps directly to trust/score inputs (high + medium).
    """
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