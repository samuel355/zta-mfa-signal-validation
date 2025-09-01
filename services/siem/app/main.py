import os, json, urllib.parse, socket, asyncio
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
import httpx

api = FastAPI(title="SIEM Connector", version="0.4")

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
    # normalize scheme for SQLAlchemy 2 + psycopg3
    if dsn.startswith("postgresql://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgresql://"):]
    elif dsn.startswith("postgres://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgres://"):]
    if "sslmode=" not in dsn:
        dsn += ("&" if "?" in dsn else "?") + "sslmode=require"
    try:
        _engine = create_engine(dsn, pool_pre_ping=True, future=True)
        with _engine.connect() as c:
            c.execute(text("select 1"))
        print(f"[DB] Engine OK for {_mask_dsn(dsn)}")
    except Exception as e:
        print(f"[DB] Engine FAIL: {e}")
        _engine = None
    return _engine

# ---- Models / normalizers ----
STRIDE_ALLOWED = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "informationdisclosure": "InformationDisclosure",
    "dos": "DoS",
    "eop": "EoP",
}
SEV_ALLOWED = {"low": "low", "medium": "medium", "high": "high", "critical": "high"}  # critical→high

def _upcase_stride(s: str) -> str:
    k = (s or "").replace("_", "").replace("-", "").replace(" ", "").lower()
    return STRIDE_ALLOWED.get(k, "InformationDisclosure")

def _norm_sev(s: str) -> str:
    k = (s or "").lower()
    return SEV_ALLOWED.get(k, "medium")

# --- dotted path helpers ---
def _get_by_dotted(d: dict, dotted: str) -> Any:
    """Return nested value for a 'a.b.c' path from dict d; None if any part missing."""
    if not dotted or not isinstance(d, dict):
        return None
    cur = d
    for part in dotted.split('.'):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur

def _ensure_str(x: Any) -> Optional[str]:
    return x if isinstance(x, str) else None

class IngestEvent(BaseModel):
    session_id: str = Field(..., description="Correlation id for session")
    severity: str = Field(..., description="low|medium|high (critical→high)")
    stride: str = Field(..., description="Spoofing|Tampering|Repudiation|InformationDisclosure|DoS|EoP")
    source: str | None = None
    raw: Dict[str, Any] = {}

def _insert_event(ev: IngestEvent):
    eng = get_engine()
    if eng is None:
        return {"ok": False, "error": "DB not configured"}
    try:
        with eng.begin() as conn:
            conn.execute(
                text("""
                    insert into zta.siem_alerts (session_id, stride, severity, source, raw)
                    select :session_id, :stride, :severity, :source, cast(:raw as jsonb)
                    where not exists (
                      select 1 from zta.siem_alerts
                      where raw->>'_id' = :es_id
                    )
                """),
                {
                    "session_id": ev.session_id,
                    "stride": _upcase_stride(ev.stride),
                    "severity": _norm_sev(ev.severity),
                    "source": ev.source,
                    "raw": json.dumps(ev.raw),
                    "es_id": ev.raw.get("_id") if isinstance(ev.raw, dict) else None,
                }
            )
        return {"ok": True}
    except Exception as ex:
        return {"ok": False, "error": str(ex)}

# ---- Health/diag ----
@api.get("/health")
def health():
    return {"status": "ok"}

@api.get("/dbcheck")
def dbcheck():
    return {"ok": get_engine() is not None}

@api.get("/dnscheck")
def dnscheck():
    dsn = os.getenv("DB_DSN", "")
    if not dsn:
        return {"ok": False, "error": "DB_DSN not set"}
    try:
        parsed = urllib.parse.urlparse(dsn.replace("postgresql+psycopg", "postgresql"))
        host = parsed.hostname
        if host is None:
            return {"ok": False, "error": "No hostname in DB_DSN"}
        ip = socket.gethostbyname(host)
        return {"ok": True, "host": host, "ip": ip}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ---- Manual ingest + Elastic webhook (if license later allows) ----
@api.post("/ingest")
def ingest(ev: IngestEvent):
    return _insert_event(ev)

@api.post("/ingest/elastic")
async def ingest_elastic(req: Request):
    payload = await req.json()
    sev = (payload.get("kibana", {}).get("alert", {}).get("severity")
           or payload.get("event", {}).get("severity") or payload.get("severity") or "medium")
    stride = (payload.get("stride") or payload.get("threat", {}).get("technique") or "InformationDisclosure")
    session_id = (payload.get("session_id")
                  or (payload.get("related", {}) or {}).get("session")
                  or (payload.get("user", {}) or {}).get("id")
                  or "sess-unknown")
    ev = IngestEvent(session_id=session_id,
                     severity=_norm_sev(str(sev)),
                     stride=_upcase_stride(str(stride)),
                     source="elastic",
                     raw=payload)
    return _insert_event(ev)

# ---- Aggregate for trust model input ----
@api.get("/aggregate")
def aggregate(session_id: str, minutes: int = 15):
    eng = get_engine()
    if eng is None:
        return {"ok": False, "error": "DB not configured"}
    sql = """
      select
        coalesce(sum((severity='high')::int),   0) as high,
        coalesce(sum((severity='medium')::int), 0) as medium,
        coalesce(sum((severity='low')::int),    0) as low
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

# ---- Background poller (FREE alternative to webhook) ----
ES_URL              = os.getenv("ES_URL", "").rstrip("/")
ES_INDEXES          = [p.strip() for p in os.getenv("ES_INDEX", "logs-*").split(",") if p.strip()]
ES_KQL              = os.getenv("ES_KQL", 'message:"auth_failure"')
ES_SESSION_FIELD    = os.getenv("ES_SESSION_FIELD", "user.id")  # supports dotted path
ES_DEFAULT_STRIDE   = os.getenv("ES_DEFAULT_STRIDE", "Tampering")
ES_DEFAULT_SEVERITY = os.getenv("ES_DEFAULT_SEVERITY", "medium")
ES_POLL_SECONDS     = int(os.getenv("ES_POLL_SECONDS", "20"))
ES_LOOKBACK         = os.getenv("ES_LOOKBACK", "2m")

async def _poll_once():
    if not ES_URL or not ES_INDEXES:
        return
    # ES query DSL: filter last window + simple query string
    q = {
        "size": 200,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "bool": {
                "must": [{"simple_query_string": {"query": ES_KQL}}],
                "filter": [{"range": {"@timestamp": {"gte": f"now-{ES_LOOKBACK}", "lte": "now"}}}]
            }
        }
    }
    headers = {"content-type": "application/json"}
    async with httpx.AsyncClient(timeout=10) as client:
        for idx in ES_INDEXES:
            try:
                r = await client.post(f"{ES_URL}/{idx}/_search", headers=headers, json=q)
                r.raise_for_status()
                body = r.json()
                hits = body.get("hits", {}).get("hits", []) or []
                print(f"[POLL] index={idx} hits={len(hits)} kql='{ES_KQL}' window='{ES_LOOKBACK}'")
                for h in hits:
                    src = h.get("_source", {}) or {}
                    # session id via dotted path (e.g., user.id)
                    sid = _ensure_str(_get_by_dotted(src, ES_SESSION_FIELD))
                    if not sid:
                        # fallback to user.name
                        sid = _ensure_str(_get_by_dotted(src, "user.name"))
                    if not sid:
                        sid = "sess-unknown"
                    # insert
                    ev = IngestEvent(
                        session_id=sid,
                        severity=ES_DEFAULT_SEVERITY,
                        stride=ES_DEFAULT_STRIDE,
                        source=f"es:{idx}",
                        raw={"_id": h.get("_id"), **src}
                    )
                    _insert_event(ev)
            except Exception as e:
                print(f"[POLL] {idx} error: {e}")

async def _poll_loop():
    # run once immediately, then at intervals
    try:
        await _poll_once()
    except Exception as e:
        print(f"[POLL] first-run error: {e}")
    while True:
        await asyncio.sleep(ES_POLL_SECONDS)
        try:
            await _poll_once()
        except Exception as e:
            print(f"[POLL] loop error: {e}")

@api.post("/poll-now")
async def poll_now():
    try:
        await _poll_once()
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@api.on_event("startup")
async def _on_start():
    # kick DB once
    get_engine()
    # launch poller if ES_URL provided
    if ES_URL:
        asyncio.create_task(_poll_loop())