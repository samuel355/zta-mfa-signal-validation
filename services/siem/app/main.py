from fastapi import FastAPI
from typing import Optional, Dict, Any, List
import os, asyncio, time, json
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

api = FastAPI(title="SIEM Connector", version="0.4")

SEV_MED = float(os.getenv("SEV_MED","0.25"))
SEV_HIGH= float(os.getenv("SEV_HIGH","0.75"))

_engine: Optional[Engine] = None
_last_ts = 0.0

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
        _engine=create_engine(dsn, pool_pre_ping=True, future=True, execution_options={"prepared_statement_cache_size": 0})
        with _engine.connect() as c: c.execute(text("select 1"))
        print(f"[DB] ok {_mask_dsn(dsn)}")
    except Exception as e:
        print(f"[DB] fail {_mask_dsn(dsn)}: {e}")
        _engine=None
    return _engine

# ----- STRIDE mapping from reasons -----
def stride_from_reasons(reasons: List[str]) -> str:
    R=set((r or "").upper() for r in reasons)
    if {"GPS_MISMATCH","WIFI_MISMATCH"} & R: return "Spoofing"
    if "TLS_ANOMALY" in R or "POSTURE_OUTDATED" in R: return "Tampering"
    if "DOS" in R: return "Denial of Service"
    if "POLICY_ELEVATION" in R: return "Elevation of Privilege"
    if "DOWNLOAD_EXFIL" in R: return "Information Disclosure"
    if "REPUDIATION" in R: return "Repudiation"
    return "Benign"

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
            with eng.begin() as conn:
                rows = conn.execute(text("""
                    select session_id, detail::jsonb as d, extract(epoch from created_at) as ts
                    from zta.mfa_events
                    where extract(epoch from created_at) > :last
                    order by created_at asc
                    limit 500
                """), {"last": _last_ts}).mappings().all()

                for r in rows:
                    d: Dict[str,Any] = r["d"]
                    reasons = d.get("reasons") or []
                    stride = stride_from_reasons(reasons)
                    risk = d.get("risk", 0.0)
                    decision = d.get("decision","allow")
                    enforcement = d.get("enforcement","ALLOW")
                    sev = severity_from_risk(risk, decision, enforcement)

                    # Check if SIEM alert already exists for this session_id and source
                    existing = conn.execute(text("""
                        select count(*) as cnt from zta.siem_alerts
                        where session_id = :sid and source like 'es:mfa-events%'
                    """), {"sid": r["session_id"]}).scalar()

                    if existing == 0:
                        conn.execute(text("""
                            insert into zta.siem_alerts (session_id, stride, severity, source, raw)
                            values (:sid, :stride, :sev, 'es:mfa-events*', cast(:raw as jsonb))
                        """), {"sid": r["session_id"], "stride": stride, "sev": sev, "raw": json.dumps(d)})
                        print(f"[siem] Created new alert for session {r['session_id']}")
                    else:
                        print(f"[siem] Skipping duplicate alert for session {r['session_id']}")

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
    eng=get_engine()
    if eng is None: return {"counts": {}}
    with eng.connect() as c:
        if session_id:
            rows=c.execute(text("""
                select severity, count(*) from zta.siem_alerts
                where session_id=:sid and created_at > now() - (:mins || ' minutes')::interval
                group by 1
            """), {"sid":session_id, "mins":minutes}).all()
        else:
            rows=c.execute(text("""
                select severity, count(*) from zta.siem_alerts
                where created_at > now() - (:mins || ' minutes')::interval
                group by 1
            """), {"mins":minutes}).all()
    return {"counts": {r[0]: int(r[1]) for r in rows}}
