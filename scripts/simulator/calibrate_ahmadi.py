"""
One-off calibration script: computes the REAL empirical mean/variance of
Ahmadi's [device_risk, location_risk, time_risk] feature dimensions across
genuine benign CIC-IDS2018 sessions, replicating _device_risk/_location_risk/
_time_risk exactly as implemented in services/ahmadi2025/app/main.py.

Run inside the simulator container (has cic2018 data mounted + EnhancedSimulator).
"""
import math
import random
import statistics
import sys
from datetime import datetime

sys.path.insert(0, "/app/scripts/simulator")
from enhanced_sim import EnhancedSimulator  # noqa: E402


def device_risk(dp):
    risk = 0.0
    if not dp.get("patched", True):
        risk += 0.35
    if not dp.get("edr", True):
        risk += 0.20
    if dp.get("compliance_score", 100) < 70:
        risk += 0.20
    return min(1.0, risk + random.uniform(0, 0.05))


def location_risk(gps):
    lat = gps.get("lat", 0.0)
    lon = gps.get("lon", 0.0)
    home_lat, home_lon = 5.6037, -0.1870
    dist = math.sqrt((lat - home_lat) ** 2 + (lon - home_lon) ** 2)
    return min(1.0, dist / 90.0 + random.uniform(0, 0.05))


def time_risk():
    h = datetime.now().hour
    if 6 <= h < 22:
        return random.uniform(0.05, 0.15)
    return random.uniform(0.50, 0.70)


def main():
    sim = EnhancedSimulator()

    dr_vals, lr_vals, tr_vals = [], [], []

    n = min(1000, len(sim.cic2018_rows))
    sample = random.sample(sim.cic2018_rows, n) if len(sim.cic2018_rows) > n else sim.cic2018_rows

    benign_count = 0
    for row in sample:
        label = (row.get("Label") or row.get("label") or "BENIGN")
        if str(label).strip().upper() != "BENIGN":
            continue
        benign_count += 1
        # Benign traffic uses the same home-weighted WiFi selection as the real
        # simulation loop (force_foreign=False) so this calibration matches the
        # actual benign location_risk distribution the service will see live.
        wifi_row = sim._pick_wifi_row(force_foreign=False)
        tls_row = sim._pick_tls_row(sim.tls_pool, bad_only=False) if sim.tls_pool else None
        dev_row = random.choice(sim.dev_pool) if sim.dev_pool else None
        sig = sim._mk_signals(row, wifi_row, tls_row, dev_row)
        dp = sig.get("device_posture", {})
        gps = sig.get("gps", {})

        dr_vals.append(device_risk(dp))
        lr_vals.append(location_risk(gps))
        tr_vals.append(time_risk())

    print(f"benign_sample_count={benign_count} (of {n} sampled, {len(sim.cic2018_rows)} total rows)")
    if len(dr_vals) < 2:
        print("Not enough benign rows to compute variance.")
        return

    print(f"device_risk:   mean={statistics.mean(dr_vals):.4f} var={statistics.variance(dr_vals):.4f}")
    print(f"location_risk: mean={statistics.mean(lr_vals):.4f} var={statistics.variance(lr_vals):.4f}")
    print(f"time_risk:     mean={statistics.mean(tr_vals):.4f} var={statistics.variance(tr_vals):.4f}")


if __name__ == "__main__":
    main()
