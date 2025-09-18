#!/usr/bin/env python3
"""
Enhanced Data Insertion Simulator
Based on original sim.py but adds baseline framework comparison
Uses proper STRIDE classification and full data complexity
"""
import os, sys, csv, json, random, time
from typing import Dict, Any, List, Optional
import httpx
import asyncio
from sqlalchemy import create_engine, text

# ------------------- Paths -------------------
DATA_DIR      = os.getenv("DATA_DIR", "/app/data")
CICIDS_DIR    = os.getenv("CICIDS_DIR", f"{DATA_DIR}/cicids")
WIFI_CSV      = os.getenv("WIFI_CSV",  f"{DATA_DIR}/wifi/wigle_sample.csv")
DEVICE_CSV    = os.getenv("DEVICE_CSV",f"{DATA_DIR}/device_posture/device_posture.csv")
TLS_CSV       = os.getenv("TLS_CSV",   f"{DATA_DIR}/tls/ja3_fingerprints.csv")

VALIDATE_URL  = os.getenv("VALIDATE_URL", "http://validation:8000/validate")
GATEWAY_URL   = os.getenv("GATEWAY_URL",  "http://gateway:8000/decision")
BASELINE_URL  = os.getenv("BASELINE_URL", "http://baseline:8000/decision")

# Database connection
DB_DSN = os.getenv("DB_DSN", "postgresql://postgres:password@localhost:5432/postgres")

# ------------------- Knobs -------------------
SLEEP_BETWEEN = float(os.getenv("SIM_SLEEP", "0.8"))
MAX_ROWS      = int(os.getenv("SIM_MAX_ROWS", "400"))
MAX_PER_FILE  = int(os.getenv("SIM_MAX_PER_FILE", "600"))
# For 24-hour simulation: 24h * 3600s/h / 1s sleep = 86400 samples
MAX_24H_SAMPLES = int(os.getenv("SIM_24H_SAMPLES", "86400"))
BENIGN_KEEP   = float(os.getenv("SIM_BENIGN_KEEP", "0.10"))
USE_GPS_FROM_WIFI = os.getenv("SIM_USE_GPS_FROM_WIFI","true").lower() in {"1","true","yes","on"}

# floors to avoid "missing"
MIN_WIFI   = float(os.getenv("SIM_MIN_WIFI", "0.9"))
MIN_GPS    = float(os.getenv("SIM_MIN_GPS", "0.85"))
MIN_TLS    = float(os.getenv("SIM_MIN_TLS", "0.7"))
MIN_DEVICE = float(os.getenv("SIM_MIN_DEVICE", "0.85"))
GPS_OFFSET_KM = float(os.getenv("SIM_GPS_OFFSET_KM","600"))

# STRIDE class mix
P_SPOOF   = float(os.getenv("SIM_PCT_SPOOFING","0.20"))
P_TLS     = float(os.getenv("SIM_PCT_TLS_TAMPERING","0.15"))
P_DOS     = float(os.getenv("SIM_PCT_DOS","0.20"))
P_EXFIL   = float(os.getenv("SIM_PCT_EXFIL","0.15"))
P_EOP     = float(os.getenv("SIM_PCT_EOP","0.15"))
P_REP     = float(os.getenv("SIM_PCT_REPUDIATION","0.15"))

class EnhancedSimulator:
    """Enhanced simulator matching original sim.py logic with baseline comparison"""

    def __init__(self):
        self.wifi_pool = []
        self.tls_pool = []
        self.dev_pool = []
        self.cicids_rows = []
        self.stride_buckets = []
        self.engine = None
        self._init_database()
        self._load_data()
        self._setup_stride_buckets()

    def _init_database(self):
        """Initialize database connection with proper error handling"""
        try:
            dsn = DB_DSN
            if dsn.startswith("postgresql://"):
                dsn = "postgresql+psycopg://" + dsn[len("postgresql://"):]
            elif dsn.startswith("postgres://"):
                dsn = "postgresql+psycopg://" + dsn[len("postgres://"):]

            # Ensure SSL for remote connections
            if "localhost" not in dsn and "127.0.0.1" not in dsn and "sslmode=" not in dsn:
                dsn += ("&" if "?" in dsn else "?") + "sslmode=require"

            self.engine = create_engine(dsn, pool_pre_ping=True)
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print(f"[DB] Connected to database successfully")
        except Exception as e:
            print(f"[DB] Failed to connect to database: {e}")
            self.engine = None

    def _read_csv(self, path):
        """Read CSV file"""
        try:
            with open(path, newline="") as f:
                return list(csv.DictReader(f))
        except Exception as e:
            print(f"[DATA] Failed to read {path}: {e}")
            return []

    def _list_csvs(self, dirpath):
        """List all CSV files in directory"""
        try:
            return [os.path.join(dirpath, f) for f in os.listdir(dirpath) if f.endswith(".csv")]
        except Exception:
            return []

    def _load_data(self):
        """Load all data pools (matching original sim.py)"""
        # Load WiFi pool
        try:
            rows = self._read_csv(WIFI_CSV)
            self.wifi_pool = [r for r in rows if (r.get("bssid") or r.get("BSSID"))]
            print(f"[DATA] Loaded {len(self.wifi_pool)} WiFi samples")
        except Exception as e:
            print(f"[DATA] Failed to load WiFi data: {e}")

        # Load TLS pool
        try:
            self.tls_pool = self._read_csv(TLS_CSV)
            print(f"[DATA] Loaded {len(self.tls_pool)} TLS samples")
        except Exception as e:
            print(f"[DATA] Failed to load TLS data: {e}")

        # Load device pool
        try:
            self.dev_pool = self._read_csv(DEVICE_CSV) or [{}]
            print(f"[DATA] Loaded {len(self.dev_pool)} device samples")
        except Exception as e:
            print(f"[DATA] Failed to load device data: {e}")

        # Load CICIDS data (matching original logic)
        cic_files = self._list_csvs(CICIDS_DIR)
        if not cic_files:
            print(f"[DATA] No CICIDS files in {CICIDS_DIR}")
            return

        rows = []
        for f in cic_files:
            try:
                r = self._read_csv(f)
                random.shuffle(r)
                attacks, benign = [], []
                for x in r:
                    lab = (x.get("Label") or x.get(" Label") or "").strip().upper()
                    if lab == "BENIGN":
                        if random.random() < BENIGN_KEEP:
                            benign.append(x)
                    else:
                        attacks.append(x)
                rows.extend((attacks + benign)[:MAX_PER_FILE])
            except Exception as e:
                print(f"[DATA] Failed to process {f}: {e}")

        random.shuffle(rows)
        self.cicids_rows = rows
        print(f"[DATA] Loaded {len(self.cicids_rows)} CICIDS samples")

    def _setup_stride_buckets(self):
        """Setup STRIDE buckets (matching original logic)"""
        buckets = [("spoof", P_SPOOF), ("tls", P_TLS), ("dos", P_DOS),
                  ("exfil", P_EXFIL), ("eop", P_EOP), ("rep", P_REP)]
        total = sum(p for _, p in buckets) or 1.0
        cum = []
        acc = 0.0
        for k, p in buckets:
            acc += p / total
            cum.append((acc, k))
        self.stride_buckets = cum

    def _get_src_ip(self, row: Dict[str, Any]) -> Optional[str]:
        """Extract source IP from CICIDS row"""
        for k, v in row.items():
            kk = str(k).replace("_", " ").strip().lower()
            if "src" in kk and "ip" in kk:
                s = str(v).strip()
                if s:
                    return s
        return None

    def _to_float(self, x) -> Optional[float]:
        """Convert to float safely"""
        try:
            return float(str(x).strip())
        except:
            return None

    def _offset_gps(self, lat, lon, km):
        """Offset GPS coordinates by given kilometers"""
        from math import radians, cos
        dlat = km / 111.0
        dlon = (km / (111.0 * max(0.15, cos(radians(lat))))) * (1 if random.random() < 0.5 else -1)
        return lat + (dlat if random.random() < 0.5 else -dlat), lon + dlon

    def _pick_tls_row(self, pool, bad_only=False):
        """Pick TLS row with weighting (matching original logic)"""
        if not pool:
            return None

        badtags = {"tor_suspect", "malware_family_x", "scanner_tool",
                  "cloud_proxy", "old_openssl", "insecure_client", "honeypot_fingerprint"}

        if bad_only:
            bad = [r for r in pool if (r.get("tag") or r.get("Tag") or "").strip().lower() in badtags]
            return random.choice(bad) if bad else None

        weights = []
        for r in pool:
            tag = (r.get("tag") or r.get("Tag") or "").strip().lower()
            weights.append(0.2 if tag in badtags else 1.0)

        try:
            return random.choices(pool, weights=weights, k=1)[0]
        except:
            return random.choice(pool)

    def _ensure_floors(self, sig):
        """Ensure minimum data presence (matching original logic)"""
        # ip_geo
        if "ip_geo" not in sig:
            sig["ip_geo"] = {"ip": f"192.0.2.{random.randint(1, 254)}"}

        # wifi + gps
        if "wifi_bssid" not in sig and self.wifi_pool:
            w = random.choice(self.wifi_pool)
            b = w.get("bssid") or w.get("BSSID")
            if b:
                sig["wifi_bssid"] = {"bssid": str(b).lower()}
                lat = self._to_float(w.get("lat") or w.get("Lat") or w.get("latitude"))
                lon = self._to_float(w.get("lon") or w.get("Lon") or w.get("longitude"))
                if lat and lon:
                    sig["gps"] = {"lat": lat, "lon": lon}

        if "gps" not in sig:
            sig["gps"] = {"lat": 37.77 + random.uniform(-0.1, 0.1),
                         "lon": -122.41 + random.uniform(-0.1, 0.1)}

        # tls
        if "tls_fp" not in sig and self.tls_pool:
            r = self._pick_tls_row(self.tls_pool, bad_only=False)
            if r and (r.get("ja3") or r.get("JA3")):
                sig["tls_fp"] = {"ja3": r.get("ja3") or r.get("JA3")}

        # device
        if "device_posture" not in sig and self.dev_pool:
            d = random.choice(self.dev_pool)
            dev_id = d.get("device_id") or d.get("Device_ID") or d.get("deviceId") or f"dev-{random.randint(1, 999)}"
            patched = str(d.get("patched", "true")).strip().lower() == "true"
            sig["device_posture"] = {"device_id": str(dev_id), "patched": patched}

    def _make_spoofing(self, sig):
        """Create spoofing scenario (matching original logic)"""
        if "wifi_bssid" not in sig or not self.wifi_pool:
            return

        bssid = str(sig.get("wifi_bssid", {}).get("bssid") or "").lower()
        if not bssid:
            return

        w = next((x for x in self.wifi_pool if str(x.get("bssid") or x.get("BSSID")).lower() == bssid), None)
        if not w:
            return

        lat = self._to_float(w.get("lat") or w.get("Lat") or w.get("latitude"))
        lon = self._to_float(w.get("lon") or w.get("Lon") or w.get("longitude"))
        if lat is None or lon is None:
            return

        g_lat, g_lon = self._offset_gps(lat, lon, GPS_OFFSET_KM)
        sig["gps"] = {"lat": g_lat, "lon": g_lon}

    def _mk_signals(self, row, wifi_row, tls_row, dev_row) -> Dict[str, Any]:
        """Create signal from data sources (matching original logic)"""
        sig = {}
        sig["session_id"] = f"sess-{random.randrange(100000, 999999)}"

        # Label from CICIDS
        lab = row.get("Label") or row.get(" Label") or row.get("LABEL")
        if lab:
            sig["label"] = str(lab).strip()

        # IP from CICIDS
        src_ip = self._get_src_ip(row)
        if src_ip:
            sig["ip_geo"] = {"ip": src_ip}

        # WiFi data
        if wifi_row:
            b = wifi_row.get("bssid") or wifi_row.get("BSSID")
            if b:
                sig["wifi_bssid"] = {"bssid": str(b).lower()}
            if USE_GPS_FROM_WIFI:
                lat = self._to_float(wifi_row.get("lat") or wifi_row.get("Lat") or wifi_row.get("latitude"))
                lon = self._to_float(wifi_row.get("lon") or wifi_row.get("Lon") or wifi_row.get("longitude"))
                if lat and lon:
                    sig["gps"] = {"lat": lat, "lon": lon}

        # Device data
        if dev_row:
            dev_id = dev_row.get("device_id") or dev_row.get("Device_ID") or dev_row.get("deviceId")
            if dev_id:
                patched_raw = str(dev_row.get("patched", "true")).strip().lower()
                patched = True if patched_raw not in {"true", "false"} else (patched_raw == "true")
                sig["device_posture"] = {"device_id": str(dev_id), "patched": patched}

        # TLS data
        if tls_row:
            ja3 = tls_row.get("ja3") or tls_row.get("JA3")
            if ja3:
                sig["tls_fp"] = {"ja3": str(ja3)}

        return sig

    def _apply_stride_scenario(self, sig, bucket):
        """Apply STRIDE scenario to signal (matching original logic)"""
        if bucket == "spoof":
            self._make_spoofing(sig)
            sig["label"] = "BENIGN"

        elif bucket == "tls":
            bad = self._pick_tls_row(self.tls_pool, bad_only=True)
            if bad and bad.get("ja3"):
                sig["tls_fp"] = {"ja3": bad.get("ja3")}
                sig["label"] = "HEARTBLEED"
            else:
                # fallback: still mark as TLS anomaly
                sig["label"] = "HEARTBLEED"

        elif bucket == "dos":
            sig["label"] = "DDOS"

        elif bucket == "exfil":
            sig["label"] = "INFILTRATION"

        elif bucket == "eop":
            sig["label"] = "WEB ATTACK"

        elif bucket == "rep":
            sig["label"] = "BENIGN"
            sig["repudiation"] = True

    async def _call_proposed_framework(self, client, sig):
        """Call proposed framework (validation -> gateway)"""
        try:
            start_time = time.perf_counter()

            # Step 1: Validation
            print(f"[PROPOSED] Calling validation for {sig['session_id']}")
            vr = await client.post(VALIDATE_URL, json={"signals": sig}, timeout=30.0)
            vr.raise_for_status()
            validated = vr.json().get("validated", {})
            print(f"[PROPOSED] Validation successful for {sig['session_id']}")

            # Step 2: Gateway decision
            print(f"[PROPOSED] Calling gateway for {sig['session_id']}")
            dr = await client.post(GATEWAY_URL, json={"validated": validated, "siem": {}}, timeout=30.0)
            dr.raise_for_status()
            decision_data = dr.json()

            end_time = time.perf_counter()
            processing_time_ms = int((end_time - start_time) * 1000)

            decision = decision_data.get("decision", "unknown")
            risk_score = decision_data.get("risk", 0.0)
            enforcement = decision_data.get("enforcement", "ALLOW")
            factors = decision_data.get("reasons", [])

            print(f"[PROPOSED] Decision for {sig['session_id']}: {decision} (risk={risk_score}, factors={factors})")

            return {
                "framework": "proposed",
                "session_id": sig["session_id"],
                "decision": decision,
                "risk_score": risk_score,
                "enforcement": enforcement,
                "factors": factors,
                "processing_time_ms": processing_time_ms,
                "full_response": decision_data
            }
        except httpx.HTTPStatusError as e:
            print(f"[PROPOSED] HTTP Error for {sig['session_id']}: {e.response.status_code} - {e.response.text}")
            return None
        except httpx.TimeoutException as e:
            print(f"[PROPOSED] Timeout for {sig['session_id']}: {e}")
            return None
        except Exception as e:
            print(f"[PROPOSED] Unexpected error for {sig['session_id']}: {e}")
            return None

    async def _call_baseline_framework(self, client, sig):
        """Call baseline framework"""
        try:
            start_time = time.perf_counter()

            print(f"[BASELINE] Calling baseline for {sig['session_id']}")
            response = await client.post(BASELINE_URL, json={"signals": sig}, timeout=30.0)
            response.raise_for_status()
            decision = response.json()

            end_time = time.perf_counter()
            processing_time_ms = int((end_time - start_time) * 1000)

            decision_val = decision.get("decision", "unknown")
            risk_score = decision.get("risk_score", 0.0)
            enforcement = decision.get("enforcement", "ALLOW")
            factors = decision.get("factors", [])

            print(f"[BASELINE] Decision for {sig['session_id']}: {decision_val} (risk={risk_score}, factors={factors})")

            return {
                "framework": "baseline",
                "session_id": sig["session_id"],
                "decision": decision_val,
                "risk_score": risk_score,
                "enforcement": enforcement,
                "factors": factors,
                "processing_time_ms": processing_time_ms,
                "full_response": decision
            }
        except httpx.HTTPStatusError as e:
            print(f"[BASELINE] HTTP Error for {sig['session_id']}: {e.response.status_code} - {e.response.text}")
            return None
        except httpx.TimeoutException as e:
            print(f"[BASELINE] Timeout for {sig['session_id']}: {e}")
            return None
        except Exception as e:
            print(f"[BASELINE] Unexpected error for {sig['session_id']}: {e}")
            return None

    def _store_comparison_data(self, comparison_id: str, proposed_result: Dict[str, Any],
                              baseline_result: Dict[str, Any], signal: Dict[str, Any]):
        """Store comparison data in database"""
        if not self.engine:
            return

        try:
            with self.engine.begin() as conn:
                # Store framework comparison data
                for result in [proposed_result, baseline_result]:
                    if result and result.get("framework") and result.get("decision") != "unknown":
                        try:
                            conn.execute(text("""
                                INSERT INTO zta.framework_comparison
                                (comparison_id, framework_type, session_id, decision, risk_score,
                                 enforcement, factors, processing_time_ms)
                                VALUES (:comp_id, :framework, :session_id, :decision, :risk_score,
                                        :enforcement, :factors, :processing_time)
                            """), {
                                "comp_id": comparison_id,
                                "framework": result["framework"],
                                "session_id": result["session_id"],
                                "decision": result["decision"],
                                "risk_score": float(result.get("risk_score", 0.0)),
                                "enforcement": result.get("enforcement", "ALLOW"),
                                "factors": json.dumps(result.get("factors", [])),
                                "processing_time": result.get("processing_time_ms", 0)
                            })
                            print(f"[DB] Stored {result['framework']} framework data: {result['decision']}")
                        except Exception as e:
                            print(f"[DB] Failed to store {result.get('framework', 'unknown')} data: {e}")

                # Store security classification data
                ground_truth = signal.get("label", "BENIGN")
                for result in [proposed_result, baseline_result]:
                    if result:
                        predicted_threats = result["factors"] if isinstance(result["factors"], list) else []

                        # Determine classification accuracy metrics
                        is_malicious_actual = ground_truth.upper() != "BENIGN"
                        has_threats_predicted = len(predicted_threats) > 0

                        false_positive = not is_malicious_actual and has_threats_predicted
                        false_negative = is_malicious_actual and not has_threats_predicted

                        conn.execute(text("""
                            INSERT INTO zta.security_classifications
                            (session_id, original_label, predicted_threats, framework_type,
                             false_positive, false_negative)
                            VALUES (:session_id, :original_label, :predicted_threats, :framework,
                                    :false_positive, :false_negative)
                        """), {
                            "session_id": result["session_id"],
                            "original_label": ground_truth,
                            "predicted_threats": json.dumps(predicted_threats),
                            "framework": result["framework"],
                            "false_positive": false_positive,
                            "false_negative": false_negative
                        })

        except Exception as e:
            print(f"[DB] Failed to store comparison data: {e}")

    async def run_simulation(self, max_samples: int = None, sleep_time: float = None):
        """Run enhanced simulation with STRIDE scenarios"""
        if max_samples is None:
            max_samples = MAX_ROWS
        if sleep_time is None:
            sleep_time = SLEEP_BETWEEN

        # Initialize data if not already done
        if not hasattr(self, 'cicids_rows') or not self.cicids_rows:
            self._init_simulator_data()

        if not self.cicids_rows:
            print("[SIM] No CICIDS data available")
            return {"comparison_id": None, "total_samples": 0, "successful_comparisons": 0}

        print(f"[SIM] pools: wifi={len(self.wifi_pool)} tls={len(self.tls_pool)} device={len(self.dev_pool)}")
        print(f"[SIM] Starting enhanced simulation with {max_samples} samples")
        print(f"[SIM] Proposed Framework: {VALIDATE_URL} -> {GATEWAY_URL}")
        print(f"[SIM] Baseline Framework: {BASELINE_URL}")

        comparison_id = f"comp-{int(time.time())}"
        sent = 0
        successful_comparisons = 0

        async with httpx.AsyncClient(timeout=60.0) as client:
            for row in self.cicids_rows:
                if sent >= max_samples:
                    break

                try:
                    # Select data sources (matching original logic)
                    wifi_row = random.choice(self.wifi_pool) if self.wifi_pool else None
                    tls_row = self._pick_tls_row(self.tls_pool, bad_only=False) if self.tls_pool else None
                    dev_row = random.choice(self.dev_pool) if self.dev_pool else None

                    # Create base signal
                    sig = self._mk_signals(row, wifi_row, tls_row, dev_row)

                    # Assign STRIDE bucket
                    r = random.random()
                    bucket = "spoof"
                    for edge, k in self.stride_buckets:
                        if r <= edge:
                            bucket = k
                            break

                    # Apply STRIDE scenario
                    self._apply_stride_scenario(sig, bucket)

                    # Ensure minimum data presence
                    self._ensure_floors(sig)

                    print(f"[SIM] Processing sample {sent+1}/{max_samples} - {sig['session_id']} (bucket: {bucket})")

                    # Call both frameworks
                    proposed_task = self._call_proposed_framework(client, sig)
                    baseline_task = self._call_baseline_framework(client, sig)

                    proposed_result, baseline_result = await asyncio.gather(
                        proposed_task, baseline_task, return_exceptions=True
                    )

                    # Handle exceptions
                    if isinstance(proposed_result, Exception):
                        print(f"[SIM] Proposed framework error: {proposed_result}")
                        proposed_result = None

                    if isinstance(baseline_result, Exception):
                        print(f"[SIM] Baseline framework error: {baseline_result}")
                        baseline_result = None

                    # Store results if we have at least one
                    if proposed_result or baseline_result:
                        self._store_comparison_data(comparison_id, proposed_result, baseline_result, sig)
                        successful_comparisons += 1

                        # Print results
                        if proposed_result and baseline_result:
                            print(f"[SIM]   Proposed: {proposed_result['decision']} (risk: {proposed_result['risk_score']:.3f}, {proposed_result['processing_time_ms']}ms)")
                            print(f"[SIM]   Baseline: {baseline_result['decision']} (risk: {baseline_result['risk_score']:.3f}, {baseline_result['processing_time_ms']}ms)")
                        elif proposed_result:
                            print(f"[SIM]   Proposed: {proposed_result['decision']} (risk: {proposed_result['risk_score']:.3f}, {proposed_result['processing_time_ms']}ms)")
                            print(f"[SIM]   Baseline: FAILED")
                        elif baseline_result:
                            print(f"[SIM]   Proposed: FAILED")
                            print(f"[SIM]   Baseline: {baseline_result['decision']} (risk: {baseline_result['risk_score']:.3f}, {baseline_result['processing_time_ms']}ms)")

                    # Sleep between requests
                    await asyncio.sleep(sleep_time)
                    sent += 1

                except KeyboardInterrupt:
                    print(f"[SIM] Simulation interrupted by user")
                    break
                except Exception as e:
                    print(f"[SIM] Unexpected error for sample {sent+1}: {e}")
                    sent += 1
                    continue

        print(f"[SIM] Simulation completed!")
        print(f"[SIM] Successful comparisons: {successful_comparisons}/{sent}")
        print(f"[SIM] Comparison ID: {comparison_id}")

        return {
            "comparison_id": comparison_id,
            "total_samples": sent,
            "successful_comparisons": successful_comparisons
        }


async def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Enhanced Data Insertion Simulator")
    parser.add_argument("--samples", type=int, default=MAX_ROWS,
                       help="Number of samples to generate")
    parser.add_argument("--sleep", type=float, default=float(os.getenv("SIM_SLEEP", "0.8")),
                       help="Sleep time between requests")

    args = parser.parse_args()

    # Create and run simulator
    simulator = EnhancedSimulator()

    try:
        result = await simulator.run_simulation(args.samples, args.sleep)
        print(f"\n[RESULT] {json.dumps(result, indent=2)}")
    except KeyboardInterrupt:
        print("\n[EXIT] Simulation interrupted")
    except Exception as e:
        print(f"\n[ERROR] Simulation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[EXIT] Simulation interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
