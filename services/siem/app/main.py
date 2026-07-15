from fastapi import FastAPI
from typing import Optional, Dict, Any, List
from collections import defaultdict
import os, asyncio, time, json
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

api = FastAPI(title="SIEM Connector", version="0.4")

SEV_MED = float(os.getenv("SEV_MED","0.25"))
SEV_HIGH= float(os.getenv("SEV_HIGH","0.75"))

_engine: Optional[Engine] = None
_last_ts = 0.0

# In-memory alert index, kept current by _worker() as it ingests mfa_events.
# /aggregate reads this instead of querying the remote DB on the decision-latency
# critical path — same rationale as backgrounding writes: a synchronous analytics
# DB round-trip has no place blocking an authentication decision.
_alert_cache: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
_ALERT_CACHE_MAX_AGE_S = 3600  # prune entries older than this on write

def _mask_dsn(dsn:str)->str:
    try:
        at = dsn.find('@')
        if '://' in dsn and at!=-1:
            head, tail = dsn.split('://',1)
            creds, rest = tail.split('@',1)
            if ':' in creds:
                user,_=creds.split(':',1)
                return f"{head}://{user}:***@{rest}"
    except: pass
    return dsn

def get_engine()->Optional[Engine]:
    global _engine
    if _engine is not None: return _engine
    dsn=os.getenv("DB_DSN","").strip()
    if not dsn:
        print("[DB] DB_DSN missing"); return None
    if dsn.startswith("postgresql://"):
        dsn="postgresql+psycopg://"+dsn[len("postgresql://"):]
    elif dsn.startswith("postgres://"):
        dsn="postgresql+psycopg://"+dsn[len("postgres://"):]
    if "sslmode=" not in dsn:
        dsn += ("&" if "?" in dsn else "?") + "sslmode=require"
    try:
        _engine=create_engine(dsn, pool_pre_ping=True, future=True,
                            pool_size=3, max_overflow=3, pool_recycle=3600,
                            connect_args={"prepare_threshold": None})
        _warm_pool(_engine, 3)
        print(f"[DB] ok {_mask_dsn(dsn)}")
    except Exception as e:
        print(f"[DB] fail {_mask_dsn(dsn)}: {e}")
        _engine=None
    return _engine

def _warm_pool(engine: Engine, n: int):
    """Eagerly open N pooled connections at startup — see validation service for rationale."""
    conns = []
    try:
        for _ in range(n):
            c = engine.connect()
            c.execute(text("select 1"))
            conns.append(c)
    finally:
        for c in conns:
            c.close()

# ----- STRIDE mapping from reasons -----
def stride_from_reasons(reasons: List[str]) -> Optional[str]:
    """Maps risk reasons to zta.siem_alerts.stride values. Must match the DB CHECK
    constraint exactly: Spoofing, Tampering, Repudiation, InformationDisclosure, DoS, EoP.
    Returns None for benign/no-STRIDE-relevant sessions — these are not alert-worthy."""
    R=set((r or "").upper() for r in reasons)
    if {"GPS_MISMATCH","WIFI_MISMATCH"} & R: return "Spoofing"
    if "TLS_ANOMALY" in R or "POSTURE_OUTDATED" in R: return "Tampering"
    if "DOS" in R: return "DoS"
    if "POLICY_ELEVATION" in R: return "EoP"
    if "DOWNLOAD_EXFIL" in R: return "InformationDisclosure"
    if "REPUDIATION" in R: return "Repudiation"
    return None

def severity_from_risk(risk: float, decision: str, enforcement: str) -> str:
    try:
        r = float(risk)
        if r >= SEV_HIGH: return "high"
        if r >= SEV_MED:  return "medium"
        return "low"
    except:
        decision = (decision or "").upper()
        enforcement = (enforcement or "").upper()
        if decision in {"BLOCK","DENY"}: return "high"
        if "MFA" in enforcement: return "medium"
        return "low"

async def _worker():
    global _last_ts
    eng = get_engine()
    if eng is None:
        print("[siem] no DB; worker disabled"); return
    while True:
        try:
            # Use a fresh connection for each iteration to avoid prepared statement issues
            with eng.connect() as conn:
                rows = conn.execute(text("""
                    select session_id, detail::jsonb as d, extract(epoch from created_at) as ts
                    from zta.mfa_events
                    where extract(epoch from created_at) > :last
                    order by created_at asc
                    limit 500
                """), {"last": _last_ts}).mappings().all()

                for r in rows:
                    session_id = r["session_id"]
                    d: Dict[str,Any] = r["d"]
                    reasons = d.get("reasons") or []
                    stride = stride_from_reasons(reasons)
                    _last_ts = float(r["ts"])
                    if stride is None:
                        continue  # benign / no STRIDE-relevant reason — not alert-worthy

                    risk = d.get("risk", 0.0)
                    decision = d.get("decision","allow")
                    enforcement = d.get("enforcement","ALLOW")
                    sev = severity_from_risk(risk, decision, enforcement)

                    existing = conn.execute(text("""
                        select count(*) as cnt from zta.siem_alerts
                        where session_id = :sid and source like 'es:mfa-events%'
                    """), {"sid": session_id}).scalar()

                    if existing == 0:
                        alert_ts = time.time()
                        conn.execute(text("""
                            insert into zta.siem_alerts (session_id, stride, severity, source, raw)
                            values (:sid, :stride, :sev, 'es:mfa-events*', CAST(:raw AS jsonb))
                        """), {"sid": session_id, "stride": stride, "sev": sev, "raw": json.dumps(d)})
                        conn.commit()

                        _alert_cache[session_id].append({"severity": sev, "ts": alert_ts})
                        cutoff = alert_ts - _ALERT_CACHE_MAX_AGE_S
                        _alert_cache[session_id] = [a for a in _alert_cache[session_id] if a["ts"] >= cutoff]

                        print(f"[siem] Created new alert for session {session_id}")
                    else:
                        print(f"[siem] Skipping duplicate alert for session {session_id}")

                    _last_ts = float(r["ts"])
        except Exception as ex:
            print(f"[siem] worker error: {ex}")
        await asyncio.sleep(3)

@api.on_event("startup")
async def start():
    asyncio.create_task(_worker())

@api.get("/health")
def health(): return {"status":"ok"}

@api.get("/aggregate")
def aggregate(session_id: Optional[str]=None, minutes: int=15):
    """Reads the in-memory alert index maintained by _worker() — no DB round-trip,
    so this stays off the authentication decision-latency critical path."""
    cutoff = time.time() - (minutes * 60)
    counts: Dict[str, int] = defaultdict(int)

    sessions = [session_id] if session_id else list(_alert_cache.keys())
    for sid in sessions:
        for alert in _alert_cache.get(sid, []):
            if alert["ts"] >= cutoff:
                counts[alert["severity"]] += 1

    return {"counts": dict(counts)}
