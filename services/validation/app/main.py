from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional
import os, json
import httpx
import joblib
import numpy as np
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from .enrichment import (
    enrich_all, DATA_STATUS, device_freshness, geo_consistency,
    device_tls_consistency, enrichment_score, DIST_THRESHOLD_KM,
)

api = FastAPI(title="Validation Service", version="0.4")

# Trained classifiers (scripts/train_dos_eop_classifiers.py), loaded once at
# process start. Each bundle carries its own feature list and threshold.
MODEL_DIR = os.getenv("ML_MODEL_DIR", "/app/models")

def _load_model(name: str):
    path = os.path.join(MODEL_DIR, f"{name}_classifier.joblib")
    try:
        bundle = joblib.load(path)
        print(f"[ML] Loaded {name} classifier: {len(bundle['feature_names'])} features, threshold={bundle['threshold']}")
        return bundle
    except Exception as e:
        print(f"[ML] Failed to load {name} classifier from {path}: {e}")
        return None

DOS_MODEL = _load_model("dos")
EOP_MODEL = _load_model("eop")
CREDENTIAL_MODEL = _load_model("credential")
INFILTRATION_MODEL = _load_model("infiltration")

class SignalPayload(BaseModel):
    signals: Dict[str, Any]

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
        _engine = create_engine(dsn, pool_pre_ping=True, future=True,
                                 pool_size=3, max_overflow=3,
                                 connect_args={"prepare_threshold": None})
        _warm_pool(_engine, 3)
        print(f"[DB] Engine created OK for {_mask_dsn(dsn)}")
    except Exception as e:
        print(f"[DB] Failed to create engine for {_mask_dsn(dsn)}: {e}")
        _engine = None
    return _engine

def _warm_pool(engine: Engine, n: int):
    """Eagerly open N pooled connections at startup, so the ~1.3s cross-region
    connection cost is paid once at boot, not mid-request."""
    conns = []
    try:
        for _ in range(n):
            c = engine.connect()
            c.execute(text("select 1"))
            conns.append(c)
    finally:
        for c in conns:
            c.close()

CRIT_TLS = {s.strip().lower() for s in (os.getenv("TLS_CRITICAL_TAGS","").split(",") if os.getenv("TLS_CRITICAL_TAGS") else [])}
if not CRIT_TLS:
    CRIT_TLS = {"tor_suspect","malware_family_x","scanner_tool","cloud_proxy","old_openssl","insecure_client","honeypot_fingerprint"}

# Saturation distance for spoofing confidence, in km — same scaling as
# trust/app/decision_engine.py's _calculate_location_validation_risk.
SPOOF_DIST_SATURATION_KM = DIST_THRESHOLD_KM * 3.0

def compute_reasons(signals: Dict[str, Any], enr: Dict[str, Any]) -> tuple[list[str], Dict[str, float]]:
    """Returns (reasons, reason_confidence): how strong the evidence was
    behind each reason. Continuous measurements (a distance, a predict_proba)
    are used directly; categorical reasons (TLS tag, patched flag,
    repudiation flag) get confidence 1.0."""
    R: list[str] = []
    conf: Dict[str, float] = {}

    # STRIDE reasons come only from observable context signals, never from
    # the ground-truth `label` field (reserved strictly for scoring).

    # Spoofing (GPS vs Wi-Fi/IP distance) — confidence scales with how far
    # past the mismatch threshold the haversine distance is.
    dist = ((enr.get("checks") or {}).get("ip_wifi_distance_km"))
    try:
        if isinstance(dist, (int, float)) and dist > DIST_THRESHOLD_KM:
            spoof_conf = min(1.0, dist / SPOOF_DIST_SATURATION_KM)
            R.extend(["SPOOFING", "GPS_MISMATCH", "WIFI_MISMATCH"])
            conf["SPOOFING"] = conf["GPS_MISMATCH"] = conf["WIFI_MISMATCH"] = round(spoof_conf, 4)
    except Exception: pass

    # Tampering via TLS / posture — categorical (list membership / boolean),
    # no continuous strength to report.
    tag = ((enr.get("tls") or {}).get("tag") or "").strip().lower()
    if tag and tag in CRIT_TLS:
        R.append("TLS_ANOMALY")
        conf["TLS_ANOMALY"] = 1.0

    dev = (enr.get("device") or {})
    sim_dev = (signals.get("device_posture") or {})
    patched = sim_dev.get("patched", dev.get("patched"))
    if isinstance(patched, bool) and not patched:
        R.append("POSTURE_OUTDATED")
        conf["POSTURE_OUTDATED"] = 1.0

    # Information Disclosure / exfiltration: require corroborated observable
    # evidence rather than a dataset label. A DLP alert alone is not enough;
    # it must agree with sensitive-data access, a novel destination, and an
    # abnormal outbound-volume ratio.
    exfil = signals.get("exfiltration_telemetry") or {}
    try:
        outbound = float(exfil.get("outbound_bytes", 0))
        baseline = max(1.0, float(exfil.get("baseline_outbound_bytes", 0)))
        ratio = outbound / baseline
        corroborated = (
            exfil.get("dlp_alert") is True
            and exfil.get("sensitive_data_accessed") is True
            and exfil.get("destination_is_new") is True
            and ratio >= 10.0
            and int(exfil.get("connections_last_5m", 0)) >= 10
        )
        if corroborated:
            R.append("EXFILTRATION")
            conf["EXFILTRATION"] = round(min(1.0, ratio / 25.0), 4)
    except (TypeError, ValueError):
        pass

    # Repudiation flag (simulator sets it directly) — boolean, no partial state.
    if signals.get("repudiation") is True:
        R.append("REPUDIATION")
        conf["REPUDIATION"] = 1.0

    # Denial of Service, from a Random Forest classifier trained on real
    # CIC-IDS2018 flow statistics (scripts/train_dos_eop_classifiers.py).
    # Train/val/test split (scripts/simulator/data_split.py) keeps this
    # model's training rows disjoint from what the live simulator draws.
    nf = signals.get("network_flow") or {}
    if DOS_MODEL is not None and nf:
        x = np.array([[nf.get(f, 0.0) for f in DOS_MODEL["feature_names"]]])
        proba = float(DOS_MODEL["model"].predict_proba(x)[0, 1])
        if proba >= DOS_MODEL["threshold"]:
            R.append("DOS")
            conf["DOS"] = round(proba, 4)

    # Elevation of Privilege (web-application attacks: XSS/SQLi/Brute-Force-Web).
    if EOP_MODEL is not None and nf:
        x = np.array([[nf.get(f, 0.0) for f in EOP_MODEL["feature_names"]]])
        proba = float(EOP_MODEL["model"].predict_proba(x)[0, 1])
        if proba >= EOP_MODEL["threshold"]:
            R.append("POLICY_ELEVATION")
            conf["POLICY_ELEVATION"] = round(proba, 4)

    if CREDENTIAL_MODEL is not None and nf:
        x = np.array([[nf.get(f, 0.0) for f in CREDENTIAL_MODEL["feature_names"]]])
        proba = float(CREDENTIAL_MODEL["model"].predict_proba(x)[0, 1])
        if proba >= CREDENTIAL_MODEL["threshold"]:
            R.append("CREDENTIAL_ATTACK")
            conf["CREDENTIAL_ATTACK"] = round(proba, 4)

    if INFILTRATION_MODEL is not None and nf:
        x = np.array([[nf.get(f, 0.0) for f in INFILTRATION_MODEL["feature_names"]]])
        proba = float(INFILTRATION_MODEL["model"].predict_proba(x)[0, 1])
        if proba >= INFILTRATION_MODEL["threshold"]:
            R.append("EXFILTRATION")
            conf["EXFILTRATION"] = round(proba, 4)

    # dedupe keep order
    out, seen = [], set()
    for r in R:
        if r and r not in seen: out.append(r); seen.add(r)
    return out, conf

def quality_checks(signals: Dict[str, Any]) -> dict:
    missing = [k for k in ("ip_geo","gps","wifi_bssid","device_posture","tls_fp") if k not in signals]
    return {"ok": True, "missing": missing}

def cross_checks(enr: Dict[str, Any]) -> dict:
    dist = (enr.get("checks") or {}).get("ip_wifi_distance_km")
    return {"ok": True, "gps_wifi_far": bool(isinstance(dist, (int,float)) and dist > DIST_THRESHOLD_KM)}

# Penalty/window knobs, env-configurable so a sweep script can vary each on its own.
MISSING_SIGNAL_PENALTY      = float(os.getenv("MISSING_SIGNAL_PENALTY", "0.3"))
GEO_MISMATCH_PENALTY        = float(os.getenv("GEO_MISMATCH_PENALTY", "0.5"))
CRIT_TLS_PENALTY            = float(os.getenv("CRIT_TLS_PENALTY", "0.2"))
DEVICE_TLS_MISMATCH_PENALTY = float(os.getenv("DEVICE_TLS_MISMATCH_PENALTY", "0.4"))
DEVICE_FRESHNESS_WINDOW_DAYS = float(os.getenv("DEVICE_FRESHNESS_WINDOW_DAYS", "30"))

_SIGNAL_KEYS = ("ip_geo", "gps", "wifi_bssid", "device_posture", "tls_fp")

def _signal_quality(key: str, signals: Dict[str, Any], e: Dict[str, Any]) -> float:
    """Qi = Fi x Ci x Ei for one signal (Section 3.3's Freshness x Consistency
    x Enrichment). Freshness only actually varies for device_posture — see
    enrichment.device_freshness's docstring for why the other four are fixed
    at Fi=1.0 rather than assigned a fabricated staleness value."""
    if key == "device_posture":
        dev_id = (signals.get("device_posture") or {}).get("device_id")
        f = device_freshness(dev_id, DEVICE_FRESHNESS_WINDOW_DAYS)
        c = device_tls_consistency(e, DEVICE_TLS_MISMATCH_PENALTY)
    elif key == "tls_fp":
        f = 1.0
        c = device_tls_consistency(e, DEVICE_TLS_MISMATCH_PENALTY)
    elif key == "gps":
        f = 1.0
        c = geo_consistency(e, GEO_MISMATCH_PENALTY)
    elif key == "wifi_bssid":
        f = 1.0
        c = geo_consistency(e, GEO_MISMATCH_PENALTY, key="gps_wifi_distance_km")
    elif key == "ip_geo":
        f = 1.0
        c = geo_consistency(e, GEO_MISMATCH_PENALTY, key="gps_ip_distance_km")
    else:
        f = c = 1.0
    en = enrichment_score(key, e, CRIT_TLS, CRIT_TLS_PENALTY)
    return f * c * en

def compute_weights(signals: Dict[str, Any], q: dict, x: dict, e: dict) -> tuple[Dict[str, float], float]:
    """Returns (normalized per-signal weights Wi, quality_confidence).

    Wi = Qi / sum(Qi), always summing to 1.0 across present signals.
    quality_confidence is the mean raw Qi before normalization, discounted by
    how many of the 5 signal types are absent — this is what
    trust/app/decision_engine.py's _assess_validation_quality reads.
    """
    present = [k for k in _SIGNAL_KEYS if k in signals]
    if not present: return {}, 0.0
    q_raw = {k: _signal_quality(k, signals, e) for k in present}
    missing_count = len(q.get("missing", []))
    completeness = 1.0 - (1.0 - MISSING_SIGNAL_PENALTY) * (missing_count / len(_SIGNAL_KEYS))
    quality_confidence = (sum(q_raw.values()) / len(q_raw)) * completeness
    s = sum(q_raw.values())
    normalized = {k: v/s for k, v in q_raw.items()} if s > 0 else {}
    return normalized, quality_confidence

def aggregate(signals: dict, w: dict, reasons: list[str], reason_confidence: Dict[str, float],
              quality_confidence: float, e: dict) -> dict:
    # also include a helper set of which signals appeared (for debug in DB)
    return {
        "vector": signals, "weights": w, "reasons": reasons,
        "reason_confidence": reason_confidence,
        "quality_confidence": quality_confidence,
        # Raw pairwise distances, forwarded so trust/app/decision_engine.py can
        # score location risk continuously instead of on presence alone.
        "checks": e.get("checks", {}),
        "signals_observed": sorted(list({*signals.keys()})),
    }

@api.on_event("startup")
def _startup():
    """Warm the DB pool before accepting traffic — uvicorn won't serve requests
    until this completes, so no request ever pays the cold-connection cost."""
    get_engine()

@api.get("/datasets")
def datasets(): return {"loaded": DATA_STATUS}

@api.get("/health")
def health(): return {"status":"ok"}

def _persist_validated_context(session_id: str, signals: dict, w: dict, q: dict, x: dict, e: dict,
                                reasons: list, reason_confidence: Dict[str, float]):
    """Fire-and-forget DB write + ES indexing — runs after the response is already
    sent, so remote round-trips do not count toward decision latency."""
    eng = get_engine()
    # No schema migration for a new column — reason_confidence rides along
    # inside the existing "quality" jsonb blob, which already has no fixed
    # shape.
    q_persist = {**q, "reason_confidence": reason_confidence}
    if eng is not None:
        try:
            with eng.begin() as conn:
                conn.execute(text("""
                    insert into zta.validated_context
                      (session_id, signals, weights, quality, cross_checks, enrichment)
                    values
                      (:session_id, cast(:signals as jsonb), cast(:weights as jsonb),
                       cast(:quality as jsonb), cast(:cross as jsonb), cast(:enrichment as jsonb))
                """), {
                    "session_id": session_id,
                    "signals": json.dumps(signals),
                    "weights": json.dumps(w),
                    "quality": json.dumps(q_persist),
                    "cross": json.dumps(x),
                    "enrichment": json.dumps(e),
                })
        except Exception as ex:
            print(f"[VALIDATION][DB] Insert failed: {ex}")

        try:
            from datetime import datetime
            es_host = os.getenv("ES_HOST", "http://elasticsearch:9200").rstrip("/")
            es_user = os.getenv("ES_USER", "")
            es_pass = os.getenv("ES_PASS", "")
            es_api_key = os.getenv("ES_API_KEY", "")
            es_index = os.getenv("ES_VALIDATED_INDEX", "validated-context")

            doc = {
                "@timestamp": datetime.utcnow().isoformat(),
                "session_id": session_id,
                "signals": signals,
                "weights": w,
                "quality": q,
                "cross_checks": x,
                "enrichment": e,
                "reasons": reasons,
                "reason_confidence": reason_confidence,
            }

            headers = {"content-type": "application/json"}
            auth = None
            if es_api_key:
                headers["Authorization"] = f"ApiKey {es_api_key}"
            elif es_user and es_pass:
                auth = httpx.BasicAuth(es_user, es_pass)

            with httpx.Client(timeout=5, headers=headers, auth=auth) as c:
                r = c.post(f"{es_host}/{es_index}/_doc", json=doc)
                r.raise_for_status()
                print(f"[VALIDATION] Indexed validated context into {es_index}")
        except Exception as ex:
            print(f"[VALIDATION] Failed to index validated context: {ex}")


@api.post("/validate")
def validate(payload: SignalPayload, background_tasks: BackgroundTasks):
    e = enrich_all(payload.signals)
    q = quality_checks(payload.signals)
    x = cross_checks(e)
    reasons, reason_confidence = compute_reasons(payload.signals, e)
    w, quality_confidence = compute_weights(payload.signals, q, x, e)
    v = aggregate(payload.signals, w, reasons, reason_confidence, quality_confidence, e)

    session_id = v["vector"].get("session_id") or f"sess-{os.urandom(4).hex()}"
    background_tasks.add_task(_persist_validated_context, session_id, payload.signals, w, q, x, e,
                               reasons, reason_confidence)
    persistence = {"ok": "scheduled"}

    return {"validated": v, "quality": q, "cross": x, "enrichment": e, "persistence": persistence}
