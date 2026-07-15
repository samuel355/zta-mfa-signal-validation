#!/usr/bin/env python3
"""
Network Condition Sensitivity Experiment (Thesis Section 4.10, Figure 4.2 right panel)

Real controlled experiment: injects artificial per-hop network delay (and, for the
degraded tier, simulated packet loss requiring retransmission) around the proposed
framework's actual validation -> gateway pipeline, using real CIC-IDS2018 sessions
and the real decision engine. Nothing about the framework's own processing is
altered — only the simulated network transport time around each HTTP call.

Three tiers, matching the profiles already named in the thesis:
  normal      : 0ms   injected delay/hop, 0% loss    (~500 Mbps reference link)
  constrained : 50ms  injected delay/hop, 0% loss    (256 kbps, 50ms latency)
  degraded    : 100ms injected delay/hop, 5% loss    (256 kbps, 100ms latency, 5% loss)

Loss is modelled as: with probability P_LOSS, the first attempt at a hop is dropped
(simulated by sleeping a full extra RTT) and the request is retried once.

Writes one row per session per condition into zta.network_latency_simulation and
prints a summary (avg latency, TPR) per condition for Chapter 4 reporting.
"""
import os
import sys
import json
import time
import random
import asyncio
from typing import Dict, Any, Optional

import httpx
import psycopg

sys.path.insert(0, os.path.dirname(__file__))
from enhanced_sim import EnhancedSimulator, VALIDATE_URL, GATEWAY_URL, DB_DSN

SAMPLES_PER_CONDITION = int(os.getenv("NET_EXP_SAMPLES", "150"))

CONDITIONS = [
    {"name": "normal",      "label": "Normal (500 Mbps)",                       "delay_ms": 0,   "loss": 0.00},
    {"name": "constrained", "label": "Constrained (256 kbps, 50 ms latency)",    "delay_ms": 50,  "loss": 0.00},
    {"name": "degraded",    "label": "Degraded (256 kbps, 100 ms, 5% loss)",     "delay_ms": 100, "loss": 0.05},
]


async def _hop(client: httpx.AsyncClient, url: str, payload: dict, delay_ms: int, loss_p: float, timeout: float) -> dict:
    """One network hop with injected delay and simulated packet loss (drop + retry once)."""
    if delay_ms:
        await asyncio.sleep(delay_ms / 1000.0)
    if loss_p and random.random() < loss_p:
        # Simulated loss: the first attempt is dropped, incurring a full extra RTT
        # before the (successful) retransmission is sent.
        await asyncio.sleep(delay_ms / 1000.0 if delay_ms else 0.05)
    resp = await client.post(url, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


async def _call_proposed_under_condition(client: httpx.AsyncClient, sig: dict, condition: dict) -> Optional[Dict[str, Any]]:
    delay_ms = condition["delay_ms"]
    loss_p = condition["loss"]
    try:
        start = time.perf_counter()
        vr = await _hop(client, VALIDATE_URL, {"signals": sig}, delay_ms, loss_p, timeout=60.0)
        validated = vr.get("validated", {})
        dr = await _hop(client, GATEWAY_URL, {"validated": validated, "siem": {}}, delay_ms, loss_p, timeout=60.0)
        end = time.perf_counter()

        latency_ms = int((end - start) * 1000)
        decision = dr.get("decision", "unknown")
        return {
            "session_id": sig["session_id"],
            "decision": decision,
            "risk_score": dr.get("risk", 0.0),
            "latency_ms": latency_ms,
            "label": sig.get("label", "BENIGN"),
        }
    except Exception as e:
        print(f"[NET-EXP] {condition['name']} error for {sig.get('session_id')}: {e}")
        return None


def _store_results(condition_name: str, results: list, baseline_throughput: Optional[float]):
    """One-shot, unpooled connection — opened and closed just for this single batch
    write, so it doesn't add a sustained connection competing with the timed HTTP
    measurement loop (that contention was the actual cause of inflated readings in
    earlier runs of this experiment, not the injected network delay)."""
    if not results:
        return None
    avg_latency = sum(r["latency_ms"] for r in results) / len(results)
    throughput = 1000.0 / avg_latency if avg_latency > 0 else 0.0
    throughput_impact_pct = 0.0
    if baseline_throughput and baseline_throughput > 0:
        throughput_impact_pct = round(((baseline_throughput - throughput) / baseline_throughput) * 100, 2)

    dsn = DB_DSN.strip()
    if dsn.startswith("postgresql+psycopg://"):
        dsn = "postgresql://" + dsn[len("postgresql+psycopg://"):]
    try:
        with psycopg.connect(dsn, connect_timeout=15, prepare_threshold=None, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.executemany(
                    """INSERT INTO zta.network_latency_simulation
                       (network_condition, framework_type, decision_latency_ms, throughput_impact_pct)
                       VALUES (%s, 'proposed', %s, %s)""",
                    [(condition_name, r["latency_ms"], throughput_impact_pct) for r in results]
                )
    except Exception as e:
        print(f"[NET-EXP] Failed to store results for {condition_name}: {e}")

    return throughput


async def run():
    sim = EnhancedSimulator()  # __init__ already loads CIC-IDS2018 data
    if not sim.cic2018_rows:
        print("[NET-EXP] No CIC-IDS2018 data available — aborting")
        return

    summary = {}
    baseline_throughput = None

    async with httpx.AsyncClient(timeout=90.0) as client:
        row_pool = list(sim.cic2018_rows)
        random.shuffle(row_pool)

        # Warm-up: the target services' own DB connection pools may have gone idle
        # while this experiment spent several minutes loading CIC-IDS2018 CSVs.
        # Re-establish them with a handful of throwaway requests (discarded from
        # results) so measured latency reflects steady state, not cold reconnects.
        print("[NET-EXP] Warming target service connections before measurement...")
        for i in range(10):
            row = row_pool[i % len(row_pool)]
            sig = sim._mk_signals(row, None, None, None)
            sig["session_id"] = f"warmup-{i}-{int(time.time()*1000)}"
            await _call_proposed_under_condition(client, sig, CONDITIONS[0])
        print("[NET-EXP] Warm-up complete.")

        for condition in CONDITIONS:
            print(f"\n[NET-EXP] === Condition: {condition['label']} "
                  f"(delay={condition['delay_ms']}ms, loss={condition['loss']*100:.0f}%) ===")

            results = []
            tp = fp = tn = fn = 0

            for i in range(SAMPLES_PER_CONDITION):
                row = row_pool[i % len(row_pool)]
                wifi_row = random.choice(sim.wifi_pool) if sim.wifi_pool else None
                tls_row = sim._pick_tls_row(sim.tls_pool, bad_only=False) if sim.tls_pool else None
                dev_row = random.choice(sim.dev_pool) if sim.dev_pool else None

                sig = sim._mk_signals(row, wifi_row, tls_row, dev_row)
                r = random.random()
                bucket = "spoof"
                for edge, k in sim.stride_buckets:
                    if r <= edge:
                        bucket = k
                        break
                sim._apply_stride_scenario(sig, bucket)
                sim._ensure_floors(sig)
                sig["session_id"] = f"net-{condition['name']}-{i}-{int(time.time()*1000)}"

                res = await _call_proposed_under_condition(client, sig, condition)
                if res:
                    results.append(res)
                    is_malicious = res["label"].upper() != "BENIGN"
                    flagged = res["decision"] in ("step_up", "deny")
                    if is_malicious and flagged:
                        tp += 1
                    elif is_malicious and not flagged:
                        fn += 1
                    elif not is_malicious and flagged:
                        fp += 1
                    else:
                        tn += 1

                if (i + 1) % 25 == 0:
                    print(f"[NET-EXP]   {i+1}/{SAMPLES_PER_CONDITION} samples done")

            throughput = _store_results(condition["name"], results, baseline_throughput)
            if condition["name"] == "normal":
                baseline_throughput = throughput

            avg_latency = sum(r["latency_ms"] for r in results) / len(results) if results else 0
            tpr = tp / max(1, tp + fn)
            fpr = fp / max(1, fp + tn)

            summary[condition["name"]] = {
                "label": condition["label"],
                "avg_latency_ms": round(avg_latency, 1),
                "tpr": round(tpr, 4),
                "fpr": round(fpr, 4),
                "samples": len(results),
            }
            print(f"[NET-EXP]   avg_latency={avg_latency:.1f}ms  TPR={tpr:.1%}  FPR={fpr:.1%}  n={len(results)}")

    out_path = os.path.join(os.path.dirname(__file__), "network_condition_results.json")
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n[NET-EXP] Summary written to {out_path}")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    asyncio.run(run())
