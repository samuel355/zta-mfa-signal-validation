# services/siem/app/main.py
from __future__ import annotations
import os, json, urllib.parse, socket, asyncio, datetime as dt
from typing import Optional, Dict, Any, List, Tuple

import httpx
from fastapi import FastAPI, Request
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

api = FastAPI(title="SIEM Connector", version="0.5")

# =====================================================================================
# ------------------------------- DATABASE (Postgres) ---------------------------------
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
    """Create a psycopg(3) engine; add sslmode=require if missing."""
    global _engine
    if _engine is not None:
        return _engine

    dsn = (os.getenv("DB_DSN", "") or "").strip()
    if not dsn:
        print("[DB] DB_DSN missing; persistence disabled")
        return None

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
        print(f"[DB] Engine FAIL for {_mask_dsn(dsn)}: {e}")
        _engine = None
    return _engine

# =====================================================================================
# ------------------------------ ELASTICSEARCH CONFIG ---------------------------------
# =====================================================================================
# Host + auth (no creds in URL)
ES_HOST     = os.getenv("ES_HOST", "http://elasticsearch:9200").rstrip("/")
ES_USER     = os.getenv("ES_USER", "")
ES_PASS     = os.getenv("ES_PASS", "")
ES_API_KEY  = os.getenv("ES_API_KEY", "")

# Index patterns
# - Gateway writes to a single index (e.g., mfa-events)
# - SIEM polls a pattern (e.g., mfa-events*) so rollover/ILM still works
ES_INDEXES: List[str] = [
    p.strip() for p in (os.getenv("ES_INDEX") or os.getenv("ES_MFA_INDEX", "mfa-events*")).split(",")
    if p.strip()
]

# Optional mirroring of every inserted alert into a separate index
ES_MIRROR           = (os.getenv("ES_MIRROR", "false").lower() == "true")
ES_MIRROR_INDEX     = os.getenv("ES_MIRROR_INDEX", "siem-alerts")  # we also write primary to siem-alerts

# Poller config
ES_POLL_SECONDS     = int(os.getenv("ES_POLL_SECONDS", "20"))
ES_LOOKBACK         = os.getenv("ES_LOOKBACK", "2m")
ES_SESSION_FIELD    = os.getenv("ES_SESSION_FIELD", "session_id")

# Severity thresholds (used when deriving from risk)
def _env_float(name: str, default: float) -> float:
    try:
        v = os.getenv(name)
        return float(v) if v is not None else default
    except Exception:
        return default

SEV_HIGH_T: float   = _env_float("SEV_HIGH", 0.75)
SEV_MED_T:  float   = _env_float("SEV_MED",  0.25)

def _es_headers_auth() -> Tuple[Dict[str, str], Optional[Tuple[str, str]]]:
    headers = {"content-type": "application/json"}
    auth = None
    if ES_API_KEY:
        headers["Authorization"] = f"ApiKey {ES_API_KEY}"
    elif ES_USER and ES_PASS:
        auth = (ES_USER, ES_PASS)
    return headers, auth

# =====================================================================================
# ------------------------- NORMALIZATION / STRIDE HELPERS ----------------------------
# =====================================================================================
STRIDE_ALLOWED = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "informationdisclosure": "InformationDisclosure",
    "dos": "DoS",
    "eop": "EoP",
}
SEV_ALLOWED = {"low": "low", "medium": "medium", "high": "high", "critical": "high"}  # critical → high

# Optional overrides: "REASON_KEY:Stride,ANOTHER_KEY:Stride"
_str_map_env = os.getenv("STRIDE_MAP_OVERRIDES", "") or ""
STRIDE_OVERRIDES: Dict[str, str] = {}
for pair in [p.strip() for p in _str_map_env.replace(";", ",").split(",") if p.strip()]:
    if ":" in pair:
        k, v = pair.split(":", 1)
        STRIDE_OVERRIDES[k.strip().upper()] = STRIDE_ALLOWED.get(
            v.strip().replace("_", "").replace("-", "").replace(" ", "").lower(),
            "InformationDisclosure"
        )

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

def _upcase_stride(s: str) -> str:
    k = (s or "").replace("_", "").replace("-", "").replace(" ", "").lower()
    return STRIDE_ALLOWED.get(k, "InformationDisclosure")

def _norm_sev(s: str) -> str:
    return SEV_ALLOWED.get((s or "").lower(), "medium")

def _to_float(x, default=None):
    try:
        if isinstance(x, (int, float)):
            return float(x)
        if isinstance(x, str):
            return float(x.strip())
    except Exception:
        pass
    return default

def _derive_severity_from(src: Dict[str, Any]) -> str:
    """risk -> severity; fallback to decision/enforcement; final default LOW."""
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

def _norm_token(s: str) -> str:
    return str(s or "").replace("-", "_").replace(" ", "_").upper()

def _first_reason_token(src: Dict[str, Any]) -> str:
    """Search common reason fields and return a normalized token."""
    candidates: List[str] = []
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

    if candidates:
        return _norm_token(candidates[0])

    # Heuristics if none present
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

def _derive_stride_from(src: Dict[str, Any]) -> str:
    """Order: explicit reasons[] → derived token → field heuristics → default."""
    rs = src.get("reasons")
    if isinstance(rs, list) and rs:
        for r in rs:
            tok = _norm_token(r)
            if tok in STRIDE_OVERRIDES:
                return STRIDE_OVERRIDES[tok]
            if tok in DEFAULT_REASON_TO_STRIDE:
                return DEFAULT_REASON_TO_STRIDE[tok]
    elif isinstance(rs, str) and rs.strip():
        tok = _norm_token(rs)
        if tok in STRIDE_OVERRIDES:
            return STRIDE_OVERRIDES[tok]
        if tok in DEFAULT_REASON_TO_STRIDE:
            return DEFAULT_REASON_TO_STRIDE[tok]

    token = _first_reason_token(src)
    if token:
        if token in STRIDE_OVERRIDES:
            return STRIDE_OVERRIDES[token]
        if token in DEFAULT_REASON_TO_STRIDE:
            return DEFAULT_REASON_TO_STRIDE[token]

    if any(src.get(k) for k in ("gps_mismatch", "ip_geo_mismatch", "wifi_mismatch", "impossible_travel")):
        return "Spoofing"
    if any(src.get(k) for k in ("tls_anomaly", "ja3_suspect", "device_unhealthy", "posture_outdated")):
        return "Tampering"
    if any(src.get(k) for k in ("exfil", "data_leak")):
        return "InformationDisclosure"
    if src.get("brute_force"):
        return "DoS"
    return "InformationDisclosure"

# =====================================================================================
# ------------------------------------ MODELS -----------------------------------------
# =====================================================================================
class IngestEvent(BaseModel):
    session_id: str = Field(..., description="Correlation id for session")
    severity: str = Field(..., description="low|medium|high (critical→high)")
    stride: str = Field(..., description="Spoofing|Tampering|Repudiation|InformationDisclosure|DoS|EoP")
    source: str | None = None
    raw: Dict[str, Any] = {}

# =====================================================================================
# --------------------------- ES WRITERS / MIRRORING ----------------------------------
# =====================================================================================
def _mirror_to_es(ev: IngestEvent):
    if not ES_MIRROR or not ES_HOST:
        return
    doc = {
        "@timestamp": dt.datetime.utcnow().isoformat(),
        "session_id": ev.session_id,
        "severity": ev.severity,
        "stride": ev.stride,
        "source": ev.source or "siem",
        "raw": ev.raw,
    }
    headers, auth = _es_headers_auth()
    try:
        with httpx.Client(timeout=3, headers=headers, auth=auth) as c:
            c.post(f"{ES_HOST}/{ES_MIRROR_INDEX}/_doc", json=doc)
    except Exception as e:
        print(f"[ES MIRROR] failed: {e}")

def _index_alert_to_es(ev: IngestEvent):
    if not ES_HOST:
        return
    doc = {
        "@timestamp": dt.datetime.utcnow().isoformat(),
        "session_id": ev.session_id,
        "stride": ev.stride,
        "severity": ev.severity,
        "source": ev.source,
        "raw": ev.raw,
    }
    headers, auth = _es_headers_auth()
    try:
        with httpx.Client(timeout=5, headers=headers, auth=auth) as c:
            r = c.post(f"{ES_HOST}/siem-alerts/_doc", json=doc)
            r.raise_for_status()
    except Exception as e:
        print(f"[ES_INDEX][siem-alerts] failed: {e}")

# =====================================================================================
# ------------------------------ DB INSERT (siem_alerts) ------------------------------
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
# --------------------------------- HEALTH / DIAG -------------------------------------
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
# --------------------------------- INGEST ENDPOINTS ----------------------------------
# =====================================================================================
@api.post("/ingest")
def ingest(ev: IngestEvent):
    return _insert_event(ev)

@api.post("/ingest/elastic")
async def ingest_elastic(req: Request):
    payload = await req.json()

    # Prefer explicit; otherwise default LOW to avoid noisy alerts
    sev = (payload.get("kibana", {}).get("alert", {}).get("severity")
           or payload.get("event", {}).get("severity")
           or payload.get("severity")
           or "low")
    stride = (payload.get("stride")
              or payload.get("threat", {}).get("technique")
              or "InformationDisclosure")
    session_id = (payload.get("session_id")
                  or payload.get("related", {}).get("session")
                  or payload.get("user", {}).get("id")
                  or payload.get("user", {}).get("name")
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
# ------------------------- AGGREGATE FOR TRUST MODEL INPUT ---------------------------
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
# ---------------------------- BACKGROUND ES POLLER -----------------------------------
# =====================================================================================
async def _poll_once():
    if not ES_HOST or not ES_INDEXES:
        return

    # Events in the recent window that resulted in enforcement actions
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
    query = {"size": 200, "sort": [{"@timestamp": {"order": "asc"}}], "query": {"bool": {"filter": must_filters}}}

    headers, auth = _es_headers_auth()
    async with httpx.AsyncClient(timeout=10, headers=headers, auth=auth) as client:
        for idx in ES_INDEXES:
            try:
                r = await client.post(f"{ES_HOST}/{idx}/_search", json=query)
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

                    sev = _derive_severity_from(src) or "low"
                    stride = _derive_stride_from(src) or "InformationDisclosure"

                    ev = IngestEvent(
                        session_id=sid,
                        severity=sev,
                        stride=stride,
                        source=f"es:{idx}",
                        raw={"_id": h.get("_id"), **src},
                    )
                    _insert_event(ev)
            except Exception as e:
                print(f"[POLL] index={idx} error: {e}")

async def _poll_loop():
    while True:
        try:
            await _poll_once()
        except Exception as e:
            print(f"[POLL] loop error: {e}")
        await asyncio.sleep(ES_POLL_SECONDS)

# =====================================================================================
# ----------------------------------- STARTUP HOOK ------------------------------------
# =====================================================================================
@api.on_event("startup")
async def _on_start():
    get_engine()  # warm DB
    if ES_HOST:
        asyncio.create_task(_poll_loop())