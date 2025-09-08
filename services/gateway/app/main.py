import os, json, socket, urllib.parse, datetime as dt
import httpx, pyotp
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

api = FastAPI(title="Gateway Service", version="0.5")

TRUST_URL = os.getenv("TRUST_URL", "http://trust:8000")
SIEM_URL  = os.getenv("SIEM_URL",  "http://siem:8000")

_engine: Optional[Engine] = None

# -------------------- Elasticsearch --------------------
def index_to_es(session_id: str, enforcement: str, risk: float, decision: str, reasons: list[str] | None):
    es_host = os.getenv("ES_HOST", "http://elasticsearch:9200").rstrip("/")
    es_user = os.getenv("ES_USER", "")
    es_pass = os.getenv("ES_PASS", "")
    es_api_key = os.getenv("ES_API_KEY", "")
    es_index = os.getenv("ES_MFA_INDEX", "mfa-events")
    if not es_host:
        print("[ES_INDEX] ES_HOST not set; skipping")
        return

    doc = {
        "@timestamp": dt.datetime.utcnow().isoformat(),
        "session_id": session_id,
        "risk": float(risk),
        "decision": decision,
        "enforcement": enforcement,
    }
    if reasons:
        doc["reasons"] = [str(r).upper() for r in reasons]

    headers = {"content-type": "application/json"}
    auth = None
    if es_api_key:
        headers["Authorization"] = f"ApiKey {es_api_key}"
    elif es_user and es_pass:
        auth = httpx.BasicAuth(es_user, es_pass)

    try:
        with httpx.Client(timeout=5, headers=headers, auth=auth) as c:
            c.post(f"{es_host}/{es_index}/_doc", json=doc)
    except Exception as e:
        print(f"[ES_INDEX] failed: {e}")

# -------------------- DB --------------------
def _mask_dsn(dsn: str) -> str:
    try:
        at = dsn.find("@")
        if "://" in dsn and at != -1:
            head, tail = dsn.split("://", 1)
            creds, rest = tail.split("@", 1)
            if ":" in creds:
                user, _ = creds.split(":", 1)
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
        dsn = "postgresql+psycopg://" + dsn[len("postgresql://") :]
    elif dsn.startswith("postgres://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgres://") :]
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

# -------------------- Health --------------------
@api.get("/health")
def health():
    return {"status": "ok"}

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
        return {"ok": True, "host": host, "ip": ip, "port": port}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# -------------------- Decision --------------------
_TOTP_SECRET = os.getenv("TOTP_SECRET", "JBSWY3DPEHPK3PXP")
totp = pyotp.TOTP(_TOTP_SECRET)

@api.post("/decision")
def decision(payload: ValidateAndDecide):
    validated = payload.validated or {}
    vector    = validated.get("vector", {}) or {}
    weights   = {k: float(v) for k, v in (validated.get("weights") or {}).items()}
    reasons   = validated.get("reasons") or []

    session_id = (
        vector.get("session_id")
        or validated.get("session_id")
        or (isinstance(vector.get("auth"), dict) and vector["auth"].get("session_id"))
        or f"sess-{os.urandom(4).hex()}"
    )

    siem_counts = {"high": 0, "medium": 0}
    try:
        with httpx.Client(timeout=3) as c:
            resp = c.get(f"{SIEM_URL}/aggregate", params={"session_id": session_id, "minutes": 15})
            resp.raise_for_status()
            counts = (resp.json() or {}).get("counts") or {}
            siem_counts["high"]   = int(counts.get("high", 0) or 0)
            siem_counts["medium"] = int(counts.get("medium", 0) or 0)
    except Exception:
        pass

    score_req = {
        "vector":  {**vector, "session_id": session_id},
        "weights": weights,
        "reasons": reasons,
        "siem":    {"high": siem_counts["high"], "medium": siem_counts["medium"]},
    }
    # ---- Trust service call ----
    try:
        with httpx.Client(timeout=5) as c:
            r = c.post(f"{TRUST_URL}/score", json=score_req)
            r.raise_for_status()
            out = r.json()
    except Exception as e:
        print(f"[GATEWAY] trust/score call failed: {e}")
        # fallback: deny by default (safe)
        out = {"risk": 1.0, "decision": "deny", "error": str(e)}

    decision = out.get("decision", "allow")
    risk = round(float(out.get("risk", 0.0)) + 1e-10, 2)
    enforcement = "ALLOW"
    detail: dict[str, Any] = {"siem_counts": siem_counts}

    if decision == "step_up":
        enforcement = "MFA_STEP_UP"; detail["otp_demo"] = totp.now()
    elif decision == "deny":
        enforcement = "DENY"

    # ---------------- DB Persistence ----------------
    persistence = {"ok": False}
    eng = get_engine()
    if eng is not None:
        try:
            params = {
                "session_id": session_id,
                "method": "gateway_policy",
                "outcome": (
                    "sent" if enforcement == "MFA_STEP_UP"
                    else "failed" if enforcement == "DENY"
                    else "success"
                ),
                "detail": json.dumps({
                    "risk": risk,
                    "decision": decision,
                    "enforcement": enforcement,
                    "reasons": reasons,
                    "stride": list({r.split("_")[0] for r in reasons}),   # STRIDE classes
                    "signals_used": list(weights.keys()),
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

    # ---------------- SIEM Persistence ----------------
    # ---------------- SIEM Persistence ----------------
    if float(risk) >= 0.25:  # only persist risky events
        eng = get_engine()
        if eng is not None:
            try:
                # Map reasons -> STRIDE values exactly as schema expects
                STRIDE_MAP = {
                    "SPOOFING": "Spoofing",
                    "TLS": "Tampering",
                    "TLS_ANOMALY": "Tampering",
                    "POSTURE": "Tampering",
                    "POSTURE_OUTDATED": "Tampering",
                    "REPUDIATION": "Repudiation",
                    "DOWNLOAD": "InformationDisclosure",
                    "EXFIL": "InformationDisclosure",
                    "DOS": "DoS",
                    "DDOS": "DoS",
                    "POLICY": "EoP",
                    "EOP": "EoP",
                }

                stride_value = None
                for r in reasons:
                    for k, v in STRIDE_MAP.items():
                        if r.upper().startswith(k):
                            stride_value = v
                            break
                    if stride_value:
                        break

                # if nothing mapped, mark Unknown safely (skip violation)
                if not stride_value:
                    stride_value = "Spoofing"

                severity = "high" if risk >= 0.7 else "medium"

                with eng.begin() as conn:
                    conn.execute(
                        text("""
                            INSERT INTO zta.siem_alerts (session_id, stride, severity, source, raw)
                            VALUES (:sid, :stride, :sev, :src, CAST(:raw AS jsonb))
                        """),
                        {
                            "sid": session_id,
                            "stride": stride_value,
                            "sev": severity,
                            "src": "es:mfa-events",
                            "raw": json.dumps({
                                "risk": risk,
                                "reasons": reasons,
                                "decision": decision,
                                "enforcement": enforcement,
                                "signals_used": list(weights.keys())
                            }),
                        }
                    )
                print(f"[GATEWAY] SIEM alert inserted for {session_id} (stride={stride_value}, risk={risk})")
            except Exception as ex:
                print(f"[GATEWAY] Failed to insert SIEM alert: {ex}")
    # ---------------- Elasticsearch index ----------------
    if decision.lower() in ("step_up", "deny"):
        index_to_es(session_id, enforcement, risk, decision, reasons)

    resp = {
        "session_id": session_id,
        "enforcement": enforcement,
        "risk": risk,
        "persistence": persistence,
    }
    if "otp_demo" in detail:
        resp["otp_demo"] = detail["otp_demo"]
    return resp