"""
Phani Kumar Kanuri (2025) - ZTA for Unified Communications
DOI: 10.70153/IJCMI/2025.17201

Equation 1 (Page 6): R_t = alpha * L_t + beta * P_t
  L_t = real-time load (bandwidth, CPU, memory, login irregularity)
  P_t = predicted behaviour load (frequency, resources, hour)

Equation 2 (Page 6): H = M / n
  H   = trust index
  M   = matched (healthy) device metrics
  n   = total metrics checked (5)

Decision (paper specifies no threshold values for H or R_t — these are our own
calibration, not transcribed from the source):
  H >= 0.6 AND R_t < 0.5  -> ALLOW
  R_t < 0.55                -> CONDITIONAL (step_up)
  otherwise (R_t >= 0.55)   -> DENY

Note: the elif clause previously read "H >= 0.4 OR R_t < 0.7". Given the
device_posture signal only ever carries 2 real boolean checks (patched, edr —
the other 3 of Eq.2's 5 checks have no real data source and always default to
"healthy"), the minimum achievable H is 0.6, making "H >= 0.4" unconditionally
true and DENY structurally unreachable regardless of R_t. Removed that dead
clause so DENY is reachable when real-time/predicted load genuinely spikes.

DENY_T was also lowered from 0.70 to 0.55 after a real ROC sweep
(scripts/compute_roc_data.py) against 4360 live sessions showed R_t never
exceeds ~0.6 given L_t/P_t's realistic component ranges (bandwidth/cpu/memory
randoms + GPS-based login irregularity for L_t; hour-of-day + session
frequency for P_t) — 0.70 was unreachable even with the dead-clause fix.
0.55 sits just above the empirical R_t ceiling for benign traffic (FPR=0 at
this threshold) while remaining reachable by the most extreme malicious
sessions (TPR~0.8% at this threshold — DENY is intentionally rare, matching
the paper's framing of it as the most severe, least-common outcome).
"""

import time
import math
import random
from datetime import datetime
from typing import Dict, Any
from fastapi import FastAPI
from pydantic import BaseModel

api = FastAPI(title="Phani 2025 ZTA Baseline", version="1.0")

ALPHA = 0.5
BETA  = 0.5
TRUST_THRESHOLD = 0.6

_decisions = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "total": 0}


def _login_irregularity(sig: Dict) -> float:
    """Legitimate signal-based proxy for the paper's 'login irregularity' term —
    GPS deviation from a reference location, mirroring what a real deployment
    would observe. Never reads the ground-truth attack label."""
    gps = sig.get("gps", {})
    lat = gps.get("lat", 0.0)
    lon = gps.get("lon", 0.0)
    home_lat, home_lon = 5.6037, -0.1870
    dist = math.sqrt((lat - home_lat) ** 2 + (lon - home_lon) ** 2)
    geo_irregularity = min(1.0, dist / 90.0)
    return min(1.0, geo_irregularity + random.uniform(0, 0.05))


def _real_time_load(sig: Dict) -> float:
    """L_t — derived from simulated load signals and login irregularity."""
    # Simulated resource utilisation (no actual server metrics in signal)
    bandwidth = random.uniform(20, 60)
    cpu       = random.uniform(20, 55)
    memory    = random.uniform(30, 60)
    base      = (bandwidth + cpu + memory) / 300.0
    irr       = _login_irregularity(sig)
    return min(1.0, base + irr * 0.3)


def _predicted_behaviour(sig: Dict) -> float:
    """P_t — derived from expected session patterns (hour-of-day, session
    frequency). Never reads the ground-truth attack label."""
    h = datetime.now().hour
    hour_component = 0.5 if (h >= 22 or h < 6) else 0.2
    freq_component = random.uniform(0.05, 0.15)
    return min(1.0, freq_component + hour_component)


def _trust_index(dp: Dict) -> float:
    """Equation 2: H = M / n (5 health metrics)."""
    checks = [
        dp.get("patched", True),
        dp.get("edr", True),
        dp.get("compliance_score", 80) >= 70,
        not dp.get("jailbroken", False),
        dp.get("os_current", True) if "os_current" in dp else True,
    ]
    M = sum(1 for c in checks if c)
    return M / len(checks)


class DecisionRequest(BaseModel):
    signals: Dict[str, Any]


@api.get("/health")
def health():
    return {"status": "ok", "service": "phani2025"}


@api.post("/decision")
def decide(req: DecisionRequest):
    start = time.perf_counter()
    sig = req.signals
    session_id = sig.get("session_id", f"ph-{int(time.time())}")

    label = sig.get("label", "BENIGN")  # ground truth — used only for scoring metrics below, never as a risk input
    dp    = sig.get("device_posture", {})

    L_t = _real_time_load(sig)
    P_t = _predicted_behaviour(sig)
    R_t = ALPHA * L_t + BETA * P_t   # Equation 1
    H   = _trust_index(dp)             # Equation 2

    if H >= TRUST_THRESHOLD and R_t < 0.5:
        decision    = "allow"
        enforcement = "ALLOW"
    elif R_t < 0.55:
        decision    = "step_up"
        enforcement = "MFA_REQUIRED"
    else:
        decision    = "deny"
        enforcement = "DENY"

    latency_ms = int((time.perf_counter() - start) * 1000)

    is_malicious = label.upper().strip() != "BENIGN"
    predicted_malicious = decision != "allow"

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
        "framework":       "phani2025",
        "decision":        decision,
        "enforcement":     enforcement,
        "risk_score":      round(R_t, 4),
        "trust_index":     round(H, 4),
        "factors": {
            "real_time_load":        round(L_t, 4),
            "predicted_behaviour":   round(P_t, 4),
            "trust_index":           round(H, 4),
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
        "framework": "phani2025",
        "total": _decisions["total"],
        "tpr": round(tpr, 4),
        "fpr": round(fpr, 4),
        "precision": round(prec, 4),
        "f1": round(f1, 4),
    }
