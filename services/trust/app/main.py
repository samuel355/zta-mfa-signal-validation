from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any, Optional
import math, os, urllib.parse, socket, json
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

api = FastAPI(title="Trust Service", version="0.2")

# ---------- Models ----------
class ValidatedPayload(BaseModel):
    vector: Dict[str, Any] = {}
    weights: Dict[str, float]
    siem: Dict[str, int] = {}

# ---------- DB engine (lazy) ----------
_engine: Optional[Engine] = None

# --- DB engine (lazy) ---
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
    """Create a psycopg (v3) engine; enforce sslmode=require."""
    global _engine
    if _engine is not None:
        return _engine

    dsn = os.getenv("DB_DSN", "").strip()
    if not dsn:
        print("[DB] DB_DSN missing; skipping persistence")
        return None

    # Force psycopg v3 driver
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
        print(f"[DB] Engine created OK for {_mask_dsn(dsn)}")
    except Exception as e:
        print(f"[DB] Failed to create engine for {_mask_dsn(dsn)}: {e}")
        _engine = None
    return _engine
# ---------- Utils ----------
def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))

# ---------- Endpoints ----------
@api.get("/health")
def health():
    return {"status": "ok"}

@api.get("/dbcheck")
def dbcheck():
    eng = get_engine()
    if eng is None:
        return {"ok": False, "error": "DB_DSN missing or invalid (engine not created)"}
    try:
        with eng.connect() as conn:
            conn.execute(text("select 1"))
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
            return {'ok': False, 'error': 'Invalid hostname'}
        port = parsed.port or 5432
        ip = socket.gethostbyname(host)
        s = socket.create_connection((ip, port), timeout=5)
        s.close()
        return {"ok": True, "host": host, "ip": ip, "port": port}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@api.post("/score")
def score(payload: ValidatedPayload):
    w = payload.weights or {}
    base = float(sum(w.values()))
    alpha, beta = 0.15, 0.07
    siem = payload.siem or {}
    siem_term = alpha * float(siem.get("high", 0)) + beta * float(siem.get("medium", 0))
    raw = base + siem_term - 1.0
    r = sigmoid(raw)

    if 0.25 <= r < 0.55:
        decision = "step_up"
    elif r >= 0.55:
        decision = "deny"
    else:
        decision = "allow"

    components = {"base": base, "siem_term": siem_term}

    # -------- Persist (safe & time-bounded) --------
    persistence = {"ok": False}
    eng = get_engine()
    if eng is not None:
        try:
            with eng.begin() as conn:
                # Belt-and-suspenders: per-transaction timeout too
                conn.execute(text("SET LOCAL statement_timeout = '3s'"))
                conn.execute(
                    text("""
                        insert into zta.trust_decisions (session_id, risk, decision, components)
                        values (:session_id, :risk, :decision, cast(:components as jsonb))
                    """),
                    {
                        "session_id": f"sess-{os.urandom(4).hex()}",
                        "risk": r,
                        "decision": decision,
                        "components": json.dumps(components),
                    }
                )
            persistence = {"ok": True}
        except Exception as ex:
            persistence = {"ok": False, "error": str(ex)}

    return {"risk": r, "decision": decision, "components": components, "persistence": persistence}