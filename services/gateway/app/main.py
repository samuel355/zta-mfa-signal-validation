import os, json, socket, urllib.parse
import httpx
import pyotp
from typing import Optional, Dict, Any
from fastapi import FastAPI
from pydantic import BaseModel

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

api = FastAPI(title="Gateway Service", version="0.2")

TRUST_URL = os.getenv("TRUST_URL", "http://trust:8000")

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
        print(f"[DB] Engine created OK for { _mask_dsn(dsn) }")
    except Exception as e:
        print(f"[DB] Failed to create engine for { _mask_dsn(dsn) }: {e}")
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

@api.post("/decision")
def decision(payload: ValidateAndDecide):
    # Call trust /score
    data = {
        "vector": payload.validated.get("vector", {}),
        "weights": payload.validated.get("weights", {}),
        "siem": payload.siem,
    }
    with httpx.Client(timeout=5) as c:
        r = c.post(f"{TRUST_URL}/score", json=data)
        r.raise_for_status()
        out = r.json()  # {risk, decision, ...}

    session_id = f"sess-{os.urandom(4).hex()}"
    decision = out.get("decision", "allow")
    risk = float(out.get("risk", 0.0))
    enforcement = "ALLOW"
    detail = {}

    if decision == "step_up":
        enforcement = "MFA_STEP_UP"
        detail = {"otp_demo": totp.now()}
    elif decision == "deny":
        enforcement = "DENY"

    # Persist MFA event
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

    # Response body
    resp = {"enforcement": enforcement, "risk": risk}
    if detail:
        resp.update(detail)
    resp["persistence"] = persistence
    return resp
