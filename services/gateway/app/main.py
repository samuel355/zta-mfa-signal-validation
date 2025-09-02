import os, json, socket, urllib.parse, datetime as dt
import httpx
import pyotp
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

api = FastAPI(title="Gateway Service", version="0.2")

TRUST_URL = os.getenv("TRUST_URL", "http://trust:8000")
SIEM_URL = os.getenv("SIEM_URL", "http://siem:8000")

# -------------------- DB engine (lazy with psycopg) --------------------
_engine: Optional[Engine] = None

def index_to_es(session_id: str, enforcement: str, risk: float, decision: str, reasons: list[str] | None):
    es_url = os.getenv("ES_URL")
    if not es_url:
        print("[ES_INDEX] ES_URL not set; skipping")
        return
    doc = {
        "@timestamp": dt.datetime.utcnow().isoformat(),
        "session_id": session_id,
        "risk": float(risk),
        "decision": decision,
        "enforcement": enforcement,
    }
    if reasons:
        # store normalized, upper-cased tokens so SIEM can map to STRIDE
        doc["reasons"] = [str(r).replace("-", "_").replace(" ", "_").upper() for r in reasons]
    try:
        with httpx.Client(timeout=3) as c:
            c.post(f"{es_url}/mfa-events/_doc", json=doc)
    except Exception as e:
        print(f"[ES_INDEX] failed: {e}")
        
# --- DB engine (lazy) ---
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

    # Force psycopg v3 driver
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
# -------------------- Models --------------------
class ValidateAndDecide(BaseModel):
    validated: Dict[str, Any]
    siem: Dict[str, int] = {}

# -------------------- Health/diagnostics --------------------
@api.get("/health")
def health(): return {"status": "ok"}

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
# Demo TOTP secret for "step_up" – in a real system this would send an OTP to user.
totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")  # demo only
# at top of file (ensure these exist)

@api.post("/decision")
def decision(payload: ValidateAndDecide):
    # --- 1) Pull validated vector/weights + session_id if present ---
    validated = payload.validated or {}
    vector    = validated.get("vector", {}) or {}
    weights   = validated.get("weights", {}) or {}
    reasons   = validated.get("reasons") or []

    # Try common places to find a session id; fallback to a generated one
    session_id = (
        vector.get("session_id")
        or validated.get("session_id")
        or (isinstance(vector.get("auth"), dict) and vector["auth"].get("session_id"))
        or f"sess-{os.urandom(4).hex()}"
    )

    # --- 2) Query SIEM connector for live severity counts for this session ---
    siem_counts = {"high": 0, "medium": 0}  # defaults if SIEM is down or empty
    try:
        with httpx.Client(timeout=3) as c:
            resp = c.get(f"{SIEM_URL}/aggregate", params={"session_id": session_id, "minutes": 15})
            resp.raise_for_status()
            counts = (resp.json() or {}).get("counts") or {}
            # trust/score currently expects only high & medium
            siem_counts["high"]   = int(counts.get("high", 0) or 0)
            siem_counts["medium"] = int(counts.get("medium", 0) or 0)
    except Exception:
        # keep defaults; do not fail the decision path because of SIEM
        pass

    # --- 3) Call trust /score with live SIEM signals ---
    score_req = {
        "vector":  vector,
        "weights": weights,
        "reasons": (validated.get("reasons") or []),
        "siem":    {"high": siem_counts["high"], "medium": siem_counts["medium"]},
    }
    try:
        with httpx.Client(timeout=5) as c:
            r = c.post(f"{TRUST_URL}/score", json=score_req)
            r.raise_for_status()
            out = r.json()  # {risk, decision, components?, persistence?}
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"trust/score error: {e!s}")

    decision   = out.get("decision", "allow")
    risk_raw       = float(out.get("risk", 0.0))
    risk = round(risk_raw + 1e-10, 2)
    enforcement = "ALLOW"
    detail: dict[str, Any] = {"siem_counts": siem_counts}

    if decision == "step_up":
        enforcement = "MFA_STEP_UP"
        detail["otp_demo"] = totp.now()
    elif decision == "deny":
        enforcement = "DENY"

    # --- 4) Persist MFA event to zta.mfa_events with SAME session_id ---
    persistence = {"ok": False}
    eng = get_engine()
    if eng is not None:
        try:
            params = {
                "session_id": session_id,
                "method": "gateway_policy",
                "outcome": "sent" if enforcement == "MFA_STEP_UP" else ("failed" if enforcement == "DENY" else "success"),
                "detail": json.dumps({
                    "risk": risk,
                    "decision": decision,
                    "enforcement": enforcement,
                    "reasons": reasons,
                    **detail
                }),
            }
            with eng.begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO zta.mfa_events (session_id, method, outcome, detail)
                        VALUES (:session_id, :method, :outcome, CAST(:detail AS jsonb))
                    """),
                    params,
                )
            persistence = {"ok": True}
        except Exception as ex:
            persistence = {"ok": False, "error": str(ex)}
    
    index_to_es(session_id, enforcement, risk, decision, reasons)

    # --- 5) Response (includes OTP for demo if step-up) ---
    resp = {"session_id": session_id, "enforcement": enforcement, "risk": risk, "persistence": persistence}
    if "otp_demo" in detail:
        resp["otp_demo"] = detail["otp_demo"]
    return resp
