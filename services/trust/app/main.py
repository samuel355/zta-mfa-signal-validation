from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any, Optional
import math
import os

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

# -------- FastAPI app --------
api = FastAPI(title="Trust Service", version="0.2")

# -------- Models --------
class ValidatedPayload(BaseModel):
    vector: Dict[str, Any] = {}
    weights: Dict[str, float]
    siem: Dict[str, int] = {}  # e.g., {"high": 0/1, "medium": 0/1}

# -------- Utils --------
def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))

DB_DSN = os.getenv("DB_DSN", "")
_engine: Optional[Engine] = None

def get_engine() -> Optional[Engine]:
    """Lazily construct the SQLAlchemy engine; return None if DSN missing/invalid."""
    global _engine
    if _engine is None:
        if not DB_DSN:
            return None
        try:
            _engine = create_engine(DB_DSN, pool_pre_ping=True, future=True)
        except Exception:
            _engine = None
    return _engine

# -------- Health --------
@api.get("/health")
def health():
    return {"status": "ok"}

# -------- Score endpoint (UPDATED) --------
@api.post("/score")
def score(payload: ValidatedPayload):
    """
    Combine validated weights with SIEM flags to produce a risk score and decision.
    Persist the outcome to zta.trust_decisions if DB_DSN is configured.
    """
    # Base from weights (simple linear sum of provided weights)
    w = payload.weights or {}
    base = float(sum(w.values()))

    # SIEM penalties (tuneable)
    alpha, beta = 0.15, 0.07
    siem_flags = payload.siem or {}
    siem_term = alpha * float(siem_flags.get("high", 0)) + beta * float(siem_flags.get("medium", 0))

    # Center around ~0 then squash
    raw = base + siem_term - 1.0
    r = sigmoid(raw)

    # Thresholds (tuneable; match thesis defaults)
    if 0.25 <= r < 0.55:
        decision = "step_up"
    elif r >= 0.55:
        decision = "deny"
    else:
        decision = "allow"

    components = {"base": base, "siem_term": siem_term}

    # ----- Persistence (safe / optional) -----
    persistence = {"ok": False}
    eng = get_engine()
    if eng is not None:
        try:
            with eng.begin() as conn:
                conn.execute(
                    text("""
                        insert into zta.trust_decisions (session_id, risk, decision, components)
                        values (:session_id, :risk, :decision, cast(:components as jsonb))
                    """),
                    {
                        "session_id": f"sess-{os.urandom(4).hex()}",
                        "risk": r,
                        "decision": decision,
                        "components": components,
                    }
                )
            persistence = {"ok": True}
        except Exception as ex:
            persistence = {"ok": False, "error": str(ex)}

    return {"risk": r, "decision": decision, "components": components, "persistence": persistence}
