"""
Jimmy (2025) - CAMFA: Context-Aware Multi-Factor Authentication
Jurnal Minfo Polgan, Vol 14, Issue 1, pp 563-567

No explicit formulae published. Implementation follows the four contextual
factors described in the paper: location, device health, time, user behaviour.

Risk = loc_w * location_risk + dev_w * device_risk
     + time_w * time_risk   + beh_w * behaviour_risk
Thresholds: ALLOW < 0.30, MFA < 0.60, DENY >= 0.60
"""

import time
import math
import random
from datetime import datetime
from typing import Dict, Any
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel

api = FastAPI(title="Jimmy 2025 CAMFA Baseline", version="1.0")

LOC_W  = 0.30
DEV_W  = 0.25
TIME_W = 0.20
BEH_W  = 0.25

DENY_T   = 0.60
STEPUP_T = 0.30

# Known-good location centroid (approximated from training set concept)
_HOME_LAT, _HOME_LON = 5.6037, -0.1870
_USUAL_HOURS = set(range(7, 21))   # 7 AM – 9 PM

_decisions = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "total": 0}


def _location_risk(gps: Dict) -> float:
    lat = float(gps.get("lat", _HOME_LAT))
    lon = float(gps.get("lon", _HOME_LON))
    dist_deg = math.sqrt((lat - _HOME_LAT) ** 2 + (lon - _HOME_LON) ** 2)
    dist_km  = dist_deg * 111.0
    return min(1.0, dist_km / 500.0 + random.uniform(0, 0.05))


def _device_risk(dp: Dict) -> float:
    trust = float(dp.get("compliance_score", 80)) / 100.0
    risk  = 1.0 - trust
    if not dp.get("patched", True):
        risk += 0.20
    if not dp.get("edr", True):
        risk += 0.15
    return min(1.0, risk)


def _time_risk() -> float:
    h = datetime.now().hour
    if h not in _USUAL_HOURS:
        return random.uniform(0.55, 0.75)
    return random.uniform(0.03, 0.12)


def _behaviour_risk(sig: Dict) -> float:
    """Legitimate signal-based proxy for CAMFA's 'user behaviour' factor —
    TLS fingerprint presence/consistency, mirroring what a real deployment
    would observe. Never reads the ground-truth attack label."""
    tls = sig.get("tls_fp", {})
    if not tls.get("ja3"):
        return random.uniform(0.30, 0.50)  # missing fingerprint is itself irregular
    return random.uniform(0.02, 0.12)


class DecisionRequest(BaseModel):
    signals: Dict[str, Any]


@api.get("/health")
def health():
    return {"status": "ok", "service": "jimmy2025"}


@api.post("/decision")
def decide(req: DecisionRequest):
    start = time.perf_counter()
    sig = req.signals
    session_id = sig.get("session_id", f"jim-{int(time.time())}")

    label = sig.get("label", "BENIGN")  # ground truth — used only for scoring metrics below, never as a risk input

    loc_r  = _location_risk(sig.get("gps", {}))
    dev_r  = _device_risk(sig.get("device_posture", {}))
    time_r = _time_risk()
    beh_r  = _behaviour_risk(sig)

    R = LOC_W * loc_r + DEV_W * dev_r + TIME_W * time_r + BEH_W * beh_r

    if R >= DENY_T:
        decision    = "deny"
        enforcement = "DENY"
    elif R >= STEPUP_T:
        decision    = "step_up"
        enforcement = "MFA_REQUIRED"
    else:
        decision    = "allow"
        enforcement = "ALLOW"

    latency_ms = int((time.perf_counter() - start) * 1000)

    is_malicious = label.upper().strip() != "BENIGN"
    predicted_malicious = R >= STEPUP_T

    _decisions["total"] += 1
    if is_malicious and predicted_malicious:
        _decisions["tp"] += 1
    elif not is_malicious and predicted_malicious:
        _decisions["fp"] += 1
    elif not is_malicious and not predicted_malicious:
        _decisions["tn"] += 1
    else:
        _decisions["fn"] += 1

    return {
        "session_id":      session_id,
        "framework":       "jimmy2025",
        "decision":        decision,
        "enforcement":     enforcement,
        "risk_score":      round(R, 4),
        "factors": {
            "location_risk":  round(loc_r, 4),
            "device_risk":    round(dev_r, 4),
            "time_risk":      round(time_r, 4),
            "behaviour_risk": round(beh_r, 4),
        },
        "processing_time_ms": latency_ms,
    }


@api.get("/stats")
def stats():
    tp, fp = _decisions["tp"], _decisions["fp"]
    tn, fn = _decisions["tn"], _decisions["fn"]
    tpr  = tp / max(1, tp + fn)
    fpr  = fp / max(1, fp + tn)
    prec = tp / max(1, tp + fp)
    f1   = 2 * prec * tpr / max(0.001, prec + tpr)
    return {
        "framework": "jimmy2025",
        "total": _decisions["total"],
        "tpr": round(tpr, 4),
        "fpr": round(fpr, 4),
        "precision": round(prec, 4),
        "f1": round(f1, 4),
    }
