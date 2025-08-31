from fastapi import FastAPI
from pydantic import BaseModel
import httpx, pyotp, os

TRUST_URL = os.getenv("TRUST_URL", "http://localhost:8002")

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

    if out["decision"] == "step_up":
        # create one-time code (placeholder)
        code = totp.now()
        return {"enforcement": "MFA_STEP_UP", "code_demo": code, "risk": out["risk"]}
    elif out["decision"] == "deny":
        return {"enforcement": "DENY", "risk": out["risk"]}
    return {"enforcement": "ALLOW", "risk": out["risk"]}
