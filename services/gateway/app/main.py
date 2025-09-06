# services/gateway/app/main.py
import os, socket, urllib.parse, datetime as dt
from typing import Optional, Dict, Any

import httpx
import pyotp
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from sqlalchemy import create_engine, text, bindparam
from sqlalchemy.engine import Engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import SQLAlchemyError

api = FastAPI(title="Gateway Service", version="0.2")

TRUST_URL = os.getenv("TRUST_URL", "http://trust:8000")
SIEM_URL  = os.getenv("SIEM_URL",  "http://siem:8000")

# -------------------- DB engine (lazy with psycopg) --------------------
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

# -------------------- Elasticsearch indexing --------------------
def index_to_es(session_id: str, enforcement: str, risk: float, decision: str, reasons: list[str] | None):
    es_host    = os.getenv("ES_HOST", "http://elasticsearch:9200").rstrip("/")
    es_user    = os.getenv("ES_USER", "")
    es_pass    = os.getenv("ES_PASS", "")
    es_api_key = os.getenv("ES_API_KEY", "")
    es_index   = os.getenv("ES_MFA_INDEX", "mfa-events")

    if not es_host:
        print("[ES_INDEX] ES_HOST not set; skipping")
        return

    doc = {
        "@timestamp": dt.datetime.utcnow().isoformat(),
        "session_id": session_id,
        "risk": float(risk),
        "decision": decision,
        "enforcement": enforcement,
    }
    if reasons:
        doc["reasons"] = [str(r).replace("-", "_").replace(" ", "_").upper() for r in reasons]

    headers = {"content-type": "application/json"}
    auth = None  # tuple works for httpx basic auth
    if es_api_key:
        headers["Authorization"] = f"ApiKey {es_api_key}"
    elif es_user and es_pass:
        auth = (es_user, es_pass)

    try:
        with httpx.Client(timeout=5, headers=headers, auth=auth) as c:
            r = c.post(f"{es_host}/{es_index}/_doc", json=doc)
            if r.status_code >= 300:
                print(f"[ES_INDEX] HTTP {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"[ES_INDEX] failed: {e}")

# -------------------- Models --------------------
class ValidateAndDecide(BaseModel):
    validated: Dict[str, Any]
    siem: Dict[str, int] = {}

# -------------------- Health/diagnostics --------------------
@api.get("/health")
def health(): 
    return {"status": "ok"}

@api.get("/dbcheck")
def dbcheck():
    eng = get_engine()
    if eng is None:
        return {"ok": False, "error": "DB_DSN missing or invalid (engine not created)"}
    try:
        with eng.connect() as c:
            c.execute(text("select 1"))
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
            return {"ok": False, "error": "No hostname found in DB_DSN"}
        port = parsed.port or 5432
        ip = socket.gethostbyname(host)
        with socket.create_connection((ip, port), timeout=5):
            pass
        return {"ok": True, "host": host, "ip": ip, "port": port}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# -------------------- Decision endpoint --------------------
_TOTP_SECRET = os.getenv("TOTP_SECRET", "JBSWY3DPEHPK3PXP")  # demo fallback ONLY
totp = pyotp.TOTP(_TOTP_SECRET)

@api.post("/decision")
def decision(payload: ValidateAndDecide):
    # 1) Pull validated + session_id
    validated = payload.validated or {}
    vector    = validated.get("vector", {}) or {}
    weights   = validated.get("weights", {}) or {}
    reasons   = validated.get("reasons") or []

    session_id = (
        vector.get("session_id")
        or validated.get("session_id")
        or (isinstance(vector.get("auth"), dict) and vector["auth"].get("session_id"))
        or f"sess-{os.urandom(4).hex()}"
    )

    # 2) SIEM aggregate (non-fatal)
    siem_counts = {"high": 0, "medium": 0}
    try:
        with httpx.Client(timeout=3) as c:
            resp = c.get(f"{SIEM_URL}/aggregate", params={"session_id": session_id, "minutes": 15})
            resp.raise_for_status()
            counts = (resp.json() or {}).get("counts") or {}
            siem_counts["high"]   = int(counts.get("high", 0) or 0)
            siem_counts["medium"] = int(counts.get("medium", 0) or 0)
    except Exception:
        pass

    # 3) Trust scoring
    score_req = {
        "vector":  vector,
        "weights": weights,
        "reasons": reasons,
        "siem":    {"high": siem_counts["high"], "medium": siem_counts["medium"]},
    }
    try:
        with httpx.Client(timeout=5) as c:
            r = c.post(f"{TRUST_URL}/score", json=score_req)
            r.raise_for_status()
            out = r.json()
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"trust/score error: {e!s}")

    decision  = out.get("decision", "allow")
    risk      = round(float(out.get("risk", 0.0)) + 1e-10, 2)

    enforcement = "ALLOW"
    detail: dict[str, Any] = {"siem_counts": siem_counts}
    if decision == "step_up":
        enforcement = "MFA_STEP_UP"
        detail["otp_demo"] = totp.now()
    elif decision == "deny":
        enforcement = "DENY"

    # 4) Persist MFA event (typed JSONB bind)
    persistence = {"ok": False}
    eng = get_engine()
    if eng is not None:
        try:
            with eng.begin() as conn:
                conn.execute(text("set local statement_timeout = '3s'"))

                stmt = text("""
                    insert into zta.mfa_events (session_id, method, outcome, detail)
                    values (:session_id, :method, :outcome, :detail)
                """).bindparams(bindparam("detail", type_=JSONB))

                conn.execute(stmt, {
                    "session_id": session_id,
                    "method": "gateway_policy",
                    "outcome": "sent" if enforcement == "MFA_STEP_UP" else ("failed" if enforcement == "DENY" else "success"),
                    "detail": {
                        "risk": risk,
                        "decision": decision,
                        "enforcement": enforcement,
                        "reasons": reasons,
                        **detail
                    },
                })
            persistence = {"ok": True}
        except SQLAlchemyError as ex:
            # rich diagnostics
            import traceback
            tb = "".join(traceback.format_exception_only(type(ex), ex)).strip()
            print(f"[DB][mfa_events] insert failed: {tb}")
            orig_msg = getattr(ex, "orig", None)
            if orig_msg is not None:
                print(f"[DB][mfa_events] driver said: {orig_msg!r}")
            persistence = {"ok": False, "error": str(ex)}
        except Exception as ex:
            print(f"[DB][mfa_events] insert failed (non-SQLA): {ex!r}")
            persistence = {"ok": False, "error": str(ex)}

    # 5) Index to ES (non-blocking for decision path)
    index_to_es(session_id, enforcement, risk, decision, reasons)

    # 6) Response (includes OTP for demo if step-up)
    resp = {"session_id": session_id, "enforcement": enforcement, "risk": risk, "persistence": persistence}
    if "otp_demo" in detail:
        resp["otp_demo"] = detail["otp_demo"]
    return resp