import httpx, pyotp, os
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

TRUST_URL = os.getenv("TRUST_URL", "http://localhost:8002")

DB_DSN = os.getenv("DB_DSN", "")
_engine: Engine | None = None
def get_engine() -> Engine | None:
    global _engine
    if _engine is None:
        if not DB_DSN:
            return None
        try:
            _engine = create_engine(DB_DSN, pool_pre_ping=True, future=True)
        except Exception:
            _engine = None
    return _engine
    

api = FastAPI(title="Gateway Service", version="0.1")
totp = pyotp.TOTP(pyotp.random_base32())

class ValidateAndDecide(BaseModel):
    validated: dict
    siem: dict = {}

@api.get("/health")
def health():
    return {"status": "ok"}

@api.post("/decision")
def decision(payload: ValidateAndDecide):
    # forward to trust service for scoring/decision
    data = {"vector": payload.validated.get("vector", {}),
            "weights": payload.validated.get("weights", {}),
            "siem": payload.siem}
    with httpx.Client(timeout=5) as c:
        r = c.post(f"{TRUST_URL}/score", json=data)
        r.raise_for_status()
        out = r.json()

    session_id = f"sess-{os.urandom(4).hex()}"
    enforcement = "ALLOW"
    detail = {}
    if out["decision"] == "step_up":
        enforcement = "MFA_STEP_UP"
        code = totp.now()
        detail = {"code_demo": code}
        response = {"enforcement": enforcement, "code_demo": code, "risk": out["risk"]}
    elif out["decision"] == "deny":
        enforcement = "DENY"
        response = {"enforcement": enforcement, "risk": out["risk"]}
    else:
        response = {"enforcement": enforcement, "risk": out["risk"]}

    # persist MFA event
    eng = get_engine()
    if eng is not None:
        try:
            with eng.begin() as conn:
                conn.execute(
                    text("""
                        insert into zta.mfa_events (session_id, method, outcome, detail)
                        values (:session_id, :method, :outcome, cast(:detail as jsonb))
                    """),
                    {
                        "session_id": session_id,
                        "method": "gateway_policy",
                        "outcome": "sent" if enforcement == "MFA_STEP_UP" else ("failed" if enforcement == "DENY" else "success"),
                        "detail": detail
                    }
                )
        except Exception as ex:
            response["persistence"] = {"ok": False, "error": str(ex)}
    return response

