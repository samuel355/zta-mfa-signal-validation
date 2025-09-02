import os, json, urllib.parse, socket, asyncio, datetime as dt
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
import httpx

api = FastAPI(title="SIEM Connector", version="0.4")

# =====================================================================================
# DB ENGINE
# =====================================================================================
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
        with _engine.connect() as c:
            c.execute(text("select 1"))
        print(f"[DB] Engine OK for {_mask_dsn(dsn)}")
    except Exception as e:
        print(f"[DB] Engine FAIL: {e}")
        _engine = None
    return _engine

# =====================================================================================
# ELASTIC CONFIG
# =====================================================================================
ES_URL = os.getenv("ES_URL", "").rstrip("/")  # e.g. http://elastic:${ELASTIC_PASSWORD}@elasticsearch:9200

# =====================================================================================
# NORMALIZERS & HELPERS (define in this order)
# =====================================================================================
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

def _to_float(x, default=None):
    try:
        if isinstance(x, (int, float)):
            return float(x)
        if isinstance(x, str):
            return float(x.strip())
    except Exception:
        pass
    return default

def _env_float(name: str, default: float) -> float:
    """Read an env var as float with a guaranteed float fallback."""
    try:
        v = os.getenv(name)
        return float(v) if v is not None else default
    except Exception:
        return default

SEV_HIGH_T: float = _env_float("SEV_HIGH", 0.75)
SEV_MED_T:  float = _env_float("SEV_MED",  0.25)

# Optional overrides: "KEY:Stride,KEY2:Stride"
_str_map_env = os.getenv("STRIDE_MAP_OVERRIDES", "") or ""
STRIDE_OVERRIDES: Dict[str, str] = {}
for pair in [p.strip() for p in _str_map_env.replace(";", ",").split(",") if p.strip()]:
    if ":" in pair:
        k, v = pair.split(":", 1)
        STRIDE_OVERRIDES[k.strip().upper()] = _upcase_stride(v.strip())

# Default reason→STRIDE guesses (uppercased reason tokens)
DEFAULT_REASON_TO_STRIDE: Dict[str, str] = {
    "GPS_MISMATCH": "Spoofing",
    "IP_GEO_MISMATCH": "Spoofing",
    "WIFI_MISMATCH": "Spoofing",
    "IMPOSSIBLE_TRAVEL": "Spoofing",
    "TLS_ANOMALY": "Tampering",
    "JA3_SUSPECT": "Tampering",
    "DEVICE_UNHEALTHY": "Tampering",
    "POSTURE_OUTDATED": "Tampering",
    "CREDENTIAL_STUFFING": "Repudiation",
    "BRUTE_FORCE": "DoS",
    "DOWNLOAD_EXFIL": "InformationDisclosure",
    "POLICY_ELEVATION": "EoP",
}


def _derive_severity_from(src: Dict[str, Any]) -> str:
    """
    risk -> severity; fallback to decision/enforcement; never compares None to float.
    """
    risk_raw = src.get("risk") or src.get("risk_score") or src.get("risk_value")
    risk: Optional[float] = _to_float(risk_raw, None)

    if isinstance(risk, float):
        if risk >= SEV_HIGH_T:
            return "high"
        if risk >= SEV_MED_T:
            return "medium"
        return "low"

    decision = str(src.get("decision") or "").upper()
    enforcement = str(src.get("enforcement") or "").upper()
    if decision in {"BLOCK", "DENY"}:
        return "high"
    if "MFA" in enforcement:
        return "medium"
    return "low"

def _first_reason_token(src: Dict[str, Any]) -> str:
    """
    Search common reason fields and return a normalized KEY token.
    """
    candidates = []
    for key in ("reasons", "reason_codes", "why", "notes", "reason"):
        v = src.get(key)
        if not v:
            continue
        if isinstance(v, str):
            candidates.append(v)
        elif isinstance(v, list):
            candidates.extend([str(x) for x in v if x is not None])
        elif isinstance(v, dict):
            candidates.extend([str(x) for x in v.values() if x is not None])

    if not candidates:
        # Heuristics if reasons absent
        if src.get("gps_mismatch") or src.get("impossible_travel"):
            return "GPS_MISMATCH"
        if src.get("wifi_mismatch") or src.get("bssid_mismatch"):
            return "WIFI_MISMATCH"
        if src.get("ip_geo_mismatch"):
            return "IP_GEO_MISMATCH"
        if src.get("tls_anomaly") or src.get("ja3_suspect"):
            return "TLS_ANOMALY"
        if src.get("device_unhealthy") or src.get("posture_outdated"):
            return "DEVICE_UNHEALTHY"
        if src.get("brute_force"):
            return "BRUTE_FORCE"
        if src.get("exfil") or src.get("data_leak"):
            return "DOWNLOAD_EXFIL"
        return ""

    token = candidates[0]
    token = token.replace("-", "_").replace(" ", "_").upper()
    return token

def _derive_stride_from(src: Dict[str, Any]) -> str:
    token = _first_reason_token(src)
    if token in STRIDE_OVERRIDES:
        return STRIDE_OVERRIDES[token]
    if token in DEFAULT_REASON_TO_STRIDE:
        return DEFAULT_REASON_TO_STRIDE[token]
    # Broad hints from fields
    if src.get("gps_mismatch") or src.get("ip_geo_mismatch") or src.get("wifi_mismatch") or src.get("impossible_travel"):
        return "Spoofing"
    if src.get("tls_anomaly") or src.get("ja3_suspect") or src.get("device_unhealthy") or src.get("posture_outdated"):
        return "Tampering"
    if src.get("exfil") or src.get("data_leak"):
        return "InformationDisclosure"
    if src.get("brute_force"):
        return "DoS"
    return "InformationDisclosure"

# =====================================================================================
# MODELS
# =====================================================================================
class IngestEvent(BaseModel):
    session_id: str = Field(..., description="Correlation id for session")
    severity: str = Field(..., description="low|medium|high (critical→high)")
    stride: str = Field(..., description="Spoofing|Tampering|Repudiation|InformationDisclosure|DoS|EoP")
    source: str | None = None
    raw: Dict[str, Any] = {}

# Mirror toggles
ES_MIRROR = os.getenv("ES_MIRROR", "false").lower() == "true"
ES_MIRROR_INDEX = os.getenv("ES_MIRROR_INDEX", "siem-alerts")

# =====================================================================================
# ELASTIC MIRRORING
# =====================================================================================
def _mirror_to_es(ev: IngestEvent):
    if not ES_MIRROR or not ES_URL:
        return
    doc = {
        "@timestamp": dt.datetime.utcnow().isoformat(),
        "session_id": ev.session_id,
        "severity": ev.severity,
        "stride": ev.stride,
        "source": ev.source or "siem",
        "raw": ev.raw,
    }
    try:
        with httpx.Client(timeout=3) as c:
            c.post(f"{ES_URL}/{ES_MIRROR_INDEX}/_doc", json=doc)
    except Exception as e:
        print(f"[ES MIRROR] failed: {e}")

def _index_alert_to_es(ev: IngestEvent):
    if not ES_URL:
        return
    doc = {
        "@timestamp": dt.datetime.utcnow().isoformat(),
        "session_id": ev.session_id,
        "stride": ev.stride,
        "severity": ev.severity,
        "source": ev.source,
        "raw": ev.raw,
    }
    try:
        with httpx.Client(timeout=5) as c:
            r = c.post(f"{ES_URL}/siem-alerts/_doc", json=doc)
            r.raise_for_status()
    except Exception as e:
        print(f"[ES_INDEX][siem-alerts] failed: {e}")

# =====================================================================================
# DB INSERT
# =====================================================================================
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
        _index_alert_to_es(ev)
        _mirror_to_es(ev)
        return {"ok": True}
    except Exception as ex:
        return {"ok": False, "error": str(ex)}

# =====================================================================================
# HEALTH / DIAG
# =====================================================================================
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

# =====================================================================================
# INGEST ENDPOINTS
# =====================================================================================
@api.post("/ingest")
def ingest(ev: IngestEvent):
    return _insert_event(ev)

@api.post("/ingest/elastic")
async def ingest_elastic(req: Request):
    payload = await req.json()
    sev = (payload.get("kibana", {}).get("alert", {}).get("severity")
           or payload.get("event", {}).get("severity")
           or payload.get("severity")
           or "medium")
    stride = (payload.get("stride")
              or payload.get("threat", {}).get("technique")
              or "InformationDisclosure")
    session_id = (payload.get("session_id")
                  or payload.get("related", {}).get("session")
                  or payload.get("user", {}).get("id")
                  or "sess-unknown")
    ev = IngestEvent(
        session_id=session_id,
        severity=_norm_sev(str(sev)),
        stride=_upcase_stride(str(stride)),
        source="elastic",
        raw=payload
    )
    return _insert_event(ev)

# =====================================================================================
# AGGREGATE FOR TRUST MODEL INPUT
# =====================================================================================
@api.get("/aggregate")
def aggregate(session_id: str, minutes: int = 15):
    eng = get_engine()
    if eng is None:
        return {"ok": False, "error": "DB not configured"}
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

# =====================================================================================
# BACKGROUND POLLER (FREE ALTERNATIVE TO WEBHOOK)
# =====================================================================================
ES_INDEXES         = [p.strip() for p in os.getenv("ES_INDEX", "logs-*").split(",") if p.strip()]
ES_KQL             = os.getenv("ES_KQL", 'message:"auth_failure"')
ES_SESSION_FIELD   = os.getenv("ES_SESSION_FIELD", "user.id")
ES_DEFAULT_STRIDE  = os.getenv("ES_DEFAULT_STRIDE", "Tampering")
ES_DEFAULT_SEVERITY= os.getenv("ES_DEFAULT_SEVERITY", "medium")
ES_POLL_SECONDS    = int(os.getenv("ES_POLL_SECONDS", "20"))
ES_LOOKBACK        = os.getenv("ES_LOOKBACK", "2m")

async def _poll_once():
    if not ES_URL or not ES_INDEXES:
        return

    # Match last ES_LOOKBACK window AND enforcement is one of the alerting actions.
    # We use terms on both .keyword and non-keyword to be robust across mappings.
    must_filters = [
        {"range": {"@timestamp": {"gte": f"now-{ES_LOOKBACK}", "lte": "now"}}},
        {
            "bool": {
                "should": [
                    {"terms": {"enforcement.keyword": ["MFA_STEP_UP", "DENY", "BLOCK"]}},
                    {"terms": {"enforcement":         ["MFA_STEP_UP", "DENY", "BLOCK"]}},
                ],
                "minimum_should_match": 1,
            }
        },
    ]

    q = {
        "size": 200,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"bool": {"filter": must_filters}},
        # Optional: fetch only fields we care about; comment out if you prefer full _source
        # "_source": ["@timestamp","session_id","risk","decision","enforcement","reasons","user","*"]
    }

    headers = {"content-type": "application/json"}
    async with httpx.AsyncClient(timeout=10) as client:
        for idx in ES_INDEXES:
            try:
                r = await client.post(f"{ES_URL}/{idx}/_search", headers=headers, json=q)
                r.raise_for_status()
                hits = r.json().get("hits", {}).get("hits", []) or []
                for h in hits:
                    src = h.get("_source", {}) or {}

                    # Resolve session id
                    sid = None
                    v = src.get(ES_SESSION_FIELD)
                    if isinstance(v, str) and v:
                        sid = v
                    if not sid:
                        user = src.get("user", {})
                        if isinstance(user, dict):
                            sid = user.get("name")
                    if not sid:
                        sid = "sess-unknown"

                    # Derive severity & stride with safe fallbacks
                    derived_sev   = _derive_severity_from(src) or ES_DEFAULT_SEVERITY
                    derived_stride = _derive_stride_from(src)  or _upcase_stride(ES_DEFAULT_STRIDE)

                    ev = IngestEvent(
                        session_id=sid,
                        severity=derived_sev,
                        stride=derived_stride,
                        source=f"es:{idx}",
                        raw={"_id": h.get("_id"), **src},
                    )
                    _insert_event(ev)
            except Exception as e:
                print(f"[POLL] {idx} error: {e}")
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
