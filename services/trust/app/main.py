from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any
import math

api = FastAPI(title="Trust Service", version="0.1")

class ValidatedPayload(BaseModel):
    vector: Dict[str, Any]
    weights: Dict[str, float]
    siem: Dict[str, int] = {}  # {"high": 0/1, "medium": 0/1}

def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))

@api.get("/health")
def health():
    return {"status": "ok"}

@api.post("/score")
def score(payload: ValidatedPayload):
    # toy scoring: sum(weights present) + siem penalties
    w = payload.weights
    base = sum(w.values())
    alpha, beta = 0.15, 0.07
    siem_term = alpha * payload.siem.get("high", 0) + beta * payload.siem.get("medium", 0)
    raw = base + siem_term - 1.0           # center roughly around 0
    r = sigmoid(raw)
    decision = "allow"
    if 0.25 <= r < 0.55:
        decision = "step_up"
    elif r >= 0.55:
        decision = "deny"
    return {"risk": r, "decision": decision, "components": {"base": base, "siem_term": siem_term}}
