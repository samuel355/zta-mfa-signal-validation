"""
Ahmadi et al. (2025) - ML-based Anomaly Detection for Zero Trust MFA
DOI: 10.1016/j.csa.2025.100106

Equation 2 (Page 5): R = w1 * A + w2 * C
  A = anomaly score (Mahalanobis distance from normal behaviour profile)
  C = contextual score  = (device_risk + location_risk + time_risk) / 3
  w1=0.6, w2=0.4, deny threshold=0.7
"""

import time
import math
import random
from datetime import datetime
from typing import Dict, Any, Optional
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel

api = FastAPI(title="Ahmadi 2025 Baseline", version="1.0")

# Paper weights (Equation 2)
W1 = 0.6   # anomaly weight
W2 = 0.4   # contextual weight
DENY_T    = 0.7
STEPUP_T  = 0.3

# Fixed normal-behaviour profile fitted on representative benign sessions.
# Feature vector: [device_risk, location_risk, time_risk, login_freq, resource_count, session_dur]
#
# device_risk/location_risk: empirically measured (mean, variance) from 333 real
# benign CIC-IDS2018 sessions run through this service's own _device_risk/
# _location_risk functions (scripts/simulator/calibrate_ahmadi.py), AFTER fixing
# a WiFi-pool sampling bug where benign sessions drew a WiFi AP uniformly from
# a pool where 8/10 entries are scattered across different continents — giving
# benign traffic a location_risk almost as scattered as genuinely spoofed
# sessions. Once fixed (benign traffic now weighted 85% toward the user's home
# AP cluster), location_risk's true benign baseline dropped from a first-pass
# measurement of mean=0.38 to mean=0.077. The original hardcoded placeholder
# mean [0.10, 0.15] was miscalibrated low enough that a genuinely benign
# session was further from "normal" than a moderately-spoofed one (A=0.160
# clean vs A=0.084 spoofed) — a backwards anomaly signal; this recalibration
# (plus the WiFi fix) corrects that.
#
# time_risk: analytically derived from _time_risk()'s own day/night uniform
# distributions (16/24 of hours ~ U(0.05,0.15), 8/24 ~ U(0.50,0.70)) via the
# law of total variance, rather than the single-run empirical sample
# (mean~0.10, var~0.0009 in both calibration runs) — that sample only covers
# whatever hour the calibration script happened to run at, and its near-zero
# variance would make the Mahalanobis distance pathologically oversensitive to
# time-of-day for any session scored at a different hour.
_MEAN = np.array([0.2709, 0.0771, 0.2667, 1.5, 2.0, 320.0])
_COV  = np.diag([0.0761, 0.0316, 0.0572, 1.0, 2.0, 8000.0])
_COV_INV = np.linalg.inv(_COV)

_decisions = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "total": 0}


def _device_risk(dp: Dict) -> float:
    risk = 0.0
    if not dp.get("patched", True):
        risk += 0.35
    if not dp.get("edr", True):
        risk += 0.20
    if dp.get("compliance_score", 100) < 70:
        risk += 0.20
    return min(1.0, risk + random.uniform(0, 0.05))


def _location_risk(gps: Dict, ip_geo: Dict) -> float:
    lat = gps.get("lat", 0.0)
    lon = gps.get("lon", 0.0)
    # Mahalanobis-style deviation from a known "home" region (KNUST campus: ~5.6N, 0.2W)
    home_lat, home_lon = 5.6037, -0.1870
    dist = math.sqrt((lat - home_lat) ** 2 + (lon - home_lon) ** 2)
    return min(1.0, dist / 90.0 + random.uniform(0, 0.05))


def _time_risk() -> float:
    h = datetime.now().hour
    if 6 <= h < 22:
        return random.uniform(0.05, 0.15)
    return random.uniform(0.50, 0.70)


def _mahalanobis_anomaly(fv: np.ndarray) -> float:
    diff = fv - _MEAN
    d2 = float(diff @ _COV_INV @ diff)
    dist = math.sqrt(max(0, d2))
    return min(1.0, dist / 5.0)


class DecisionRequest(BaseModel):
    signals: Dict[str, Any]


@api.get("/health")
def health():
    return {"status": "ok", "service": "ahmadi2025"}


@api.post("/decision")
def decide(req: DecisionRequest):
    start = time.perf_counter()
    sig = req.signals
    session_id = sig.get("session_id", f"ahm-{int(time.time())}")

    dp  = sig.get("device_posture", {})
    gps = sig.get("gps", {})
    ip  = sig.get("ip_geo", {})

    device_risk   = _device_risk(dp)
    location_risk = _location_risk(gps, ip)
    time_risk     = _time_risk()

    # Feature vector for Mahalanobis
    fv = np.array([
        device_risk,
        location_risk,
        time_risk,
        1.5,    # login_frequency (not in signal, use mean)
        2.0,    # resource_count (not in signal, use mean)
        300.0,  # session_duration (not in signal, use mean)
    ])

    label = sig.get("label", "BENIGN")  # ground truth — used only for scoring metrics below, never as a risk input

    A = _mahalanobis_anomaly(fv)

    C = (device_risk + location_risk + time_risk) / 3.0

    # Equation 2
    R = W1 * A + W2 * C

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
        "framework":       "ahmadi2025",
        "decision":        decision,
        "enforcement":     enforcement,
        "risk_score":      round(R, 4),
        "anomaly_score":   round(A, 4),
        "contextual_score": round(C, 4),
        "factors":         {"device_risk": device_risk, "location_risk": location_risk, "time_risk": time_risk},
        "processing_time_ms": latency_ms,
    }


@api.get("/stats")
def stats():
    t = _decisions["total"] or 1
    tp, fp = _decisions["tp"], _decisions["fp"]
    tn, fn = _decisions["tn"], _decisions["fn"]
    tpr = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    prec = tp / max(1, tp + fp)
    f1   = 2 * prec * tpr / max(0.001, prec + tpr)
    return {
        "framework": "ahmadi2025",
        "total": t,
        "tpr": round(tpr, 4),
        "fpr": round(fpr, 4),
        "precision": round(prec, 4),
        "f1": round(f1, 4),
    }
