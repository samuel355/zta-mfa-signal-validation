#!/usr/bin/env python3
"""
Real sensitivity sweep for the three signal-weight penalty constants
(MISSING_SIGNAL_PENALTY, GEO_MISMATCH_PENALTY, CRIT_TLS_PENALTY) now that
quality_confidence actually feeds into the proposed framework's decisions
(see services/validation/app/main.py and trust/app/decision_engine.py).

Replays the real signal payloads already collected in zta.validated_context
against validation -> gateway -> trust for each configuration, holding the
other two constants at baseline. This avoids a full ~15-minute simulator run
(CIC2018/RBA loading, etc.) per sweep point — the signals are already real and
already have known ground truth (embedded label field).

Requires: `docker compose up -d validation gateway trust` with the target env
vars set before each configuration's pass (this script restarts the
validation container itself between configs).
"""
import asyncio, json, os, subprocess, sys
import httpx
from sqlalchemy import create_engine, text

DB_DSN = os.environ["DB_DSN"]
dsn = DB_DSN
if dsn.startswith("postgresql://"):
    dsn = "postgresql+psycopg://" + dsn[len("postgresql://"):]

VALIDATE_URL = "http://localhost:8001/validate"
GATEWAY_URL = "http://localhost:8003/decision"
COMPOSE_FILE = "compose/docker-compose.yml"

SAMPLE_MALICIOUS = 1200
CONCURRENCY = 24

BASELINE = {"MISSING_SIGNAL_PENALTY": "0.3", "GEO_MISMATCH_PENALTY": "0.5", "CRIT_TLS_PENALTY": "0.2"}

SWEEP = [
    ("MISSING_SIGNAL_PENALTY", "0.05"),
    ("MISSING_SIGNAL_PENALTY", "0.6"),
    ("MISSING_SIGNAL_PENALTY", "0.9"),
    ("GEO_MISMATCH_PENALTY", "0.1"),
    ("GEO_MISMATCH_PENALTY", "0.7"),
    ("GEO_MISMATCH_PENALTY", "0.9"),
    ("CRIT_TLS_PENALTY", "0.05"),
    ("CRIT_TLS_PENALTY", "0.4"),
    ("CRIT_TLS_PENALTY", "0.6"),
]


def load_sample():
    eng = create_engine(dsn)
    with eng.connect() as c:
        r = c.execute(text("""
            select signals from zta.validated_context
            where signals->>'label' = 'Benign'
        """))
        benign = [row[0] for row in r]
        r = c.execute(text(f"""
            select signals from zta.validated_context
            where signals->>'label' != 'Benign'
            order by random() limit {SAMPLE_MALICIOUS}
        """))
        malicious = [row[0] for row in r]
    print(f"[sweep] loaded {len(benign)} benign + {len(malicious)} malicious = {len(benign)+len(malicious)} sessions", file=sys.stderr)
    return benign, malicious


def restart_validation(env_overrides: dict):
    env = os.environ.copy()
    env.update(BASELINE)
    env.update(env_overrides)
    subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, "up", "-d", "validation"],
        env=env, check=True, capture_output=True,
    )
    # wait for health
    import time
    for _ in range(60):
        try:
            r = httpx.get("http://localhost:8001/health", timeout=2)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError("validation service did not become healthy")


async def replay_one(client: httpx.AsyncClient, signals: dict, sem: asyncio.Semaphore):
    async with sem:
        try:
            vr = await client.post(VALIDATE_URL, json={"signals": signals}, timeout=15.0)
            vr.raise_for_status()
            validated = vr.json().get("validated", {})
            dr = await client.post(GATEWAY_URL, json={"validated": validated, "siem": {}}, timeout=15.0)
            dr.raise_for_status()
            decision = dr.json().get("decision", "allow")
        except Exception as e:
            return None
        label = (signals.get("label") or "BENIGN")
        is_malicious = label.upper() != "BENIGN"
        predicted_malicious = decision in ("step_up", "deny")
        return (is_malicious, predicted_malicious)


async def run_config(all_signals):
    sem = asyncio.Semaphore(CONCURRENCY)
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*[replay_one(client, s, sem) for s in all_signals])
    results = [r for r in results if r is not None]
    tp = sum(1 for m, p in results if m and p)
    fn = sum(1 for m, p in results if m and not p)
    fp = sum(1 for m, p in results if not m and p)
    tn = sum(1 for m, p in results if not m and not p)
    tpr = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * tpr / max(1e-9, precision + tpr)
    return {"n": len(results), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "tpr": round(tpr, 4), "fpr": round(fpr, 4), "precision": round(precision, 4), "f1": round(f1, 4)}


def main():
    benign, malicious = load_sample()
    all_signals = benign + malicious

    results = {}

    print("[sweep] === baseline ===", file=sys.stderr)
    restart_validation({})
    results["baseline"] = asyncio.run(run_config(all_signals))
    print("baseline:", results["baseline"], file=sys.stderr)

    for param, value in SWEEP:
        key = f"{param}={value}"
        print(f"[sweep] === {key} ===", file=sys.stderr)
        restart_validation({param: value})
        results[key] = asyncio.run(run_config(all_signals))
        print(key, ":", results[key], file=sys.stderr)

    # restore baseline
    restart_validation({})

    with open("scripts/sensitivity_sweep_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
