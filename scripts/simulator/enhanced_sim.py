#!/usr/bin/env python3
"""
Enhanced Data Insertion Simulator
Based on original sim.py but adds baseline framework comparison
Uses proper STRIDE classification and full data complexity
"""
import os, sys, csv, json, random, time, uuid
from typing import Dict, Any, Optional
import httpx
import asyncio
from sqlalchemy import create_engine, text

from country_centroids import COUNTRY_CENTROIDS
from data_split import split_bucket, is_split_file

# ------------------- Paths -------------------
DATA_DIR      = os.getenv("DATA_DIR", "/app/data")
CIC2018_DIR   = os.getenv("CIC2018_DIR", f"{DATA_DIR}/cic2018")
WIFI_CSV      = os.getenv("WIFI_CSV",  f"{DATA_DIR}/wifi/wigle_sample.csv")
DEVICE_CSV    = os.getenv("DEVICE_CSV",f"{DATA_DIR}/device_posture/device_posture.csv")
TLS_CSV       = os.getenv("TLS_CSV",   f"{DATA_DIR}/tls/ja3_fingerprints.csv")
RBA_CSV       = os.getenv("RBA_CSV",   f"{DATA_DIR}/rba/rba_sample.csv")

VALIDATE_URL  = os.getenv("VALIDATE_URL", "http://validation:8000/validate")
GATEWAY_URL   = os.getenv("GATEWAY_URL",  "http://gateway:8000/decision")
ABLATION_URL  = os.getenv("ABLATION_URL", "http://ablation:8000/decision")
AHMADI_URL    = os.getenv("AHMADI_URL",   "http://ahmadi2025:8000/decision")
JIMMY_URL     = os.getenv("JIMMY_URL",    "http://jimmy2025:8000/decision")
PHANI_URL     = os.getenv("PHANI_URL",    "http://phani2025:8000/decision")

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

# WiFi pool BSSIDs treated as the user's known/home access points. The pool
# also contains globally-scattered entries for spoofing scenarios to draw
# from; HOME_BSSID_PCT controls how often a non-spoof session draws from the
# home cluster instead of the full pool.
HOME_BSSIDS = {"00:11:22:33:44:55", "00:11:22:33:44:66"}
HOME_BSSID_PCT = float(os.getenv("SIM_HOME_BSSID_PCT", "0.85"))

# STRIDE class mix, normalized to sum to 1.0 with P_BENIGN. P_BENIGN reserves
# an explicit no-scenario path that keeps the real CIC-IDS2018 label untouched.
P_SPOOF   = float(os.getenv("SIM_PCT_SPOOFING","0.15"))
P_TLS     = float(os.getenv("SIM_PCT_TLS_TAMPERING","0.12"))
P_DOS     = float(os.getenv("SIM_PCT_DOS","0.18"))
P_EXFIL   = float(os.getenv("SIM_PCT_EXFIL","0.12"))
P_EOP     = float(os.getenv("SIM_PCT_EOP","0.15"))
P_REP     = float(os.getenv("SIM_PCT_REPUDIATION","0.08"))
P_BENIGN  = float(os.getenv("SIM_PCT_BENIGN","0.20"))
# Information Disclosure can be evaluated in two modes: "observable" builds a
# documented synthetic exfiltration scenario; "native" draws real
# CIC-IDS2018 Infiltration/Bot rows instead.
EXFIL_MODE = os.getenv("SIM_EXFIL_MODE", "observable").strip().lower()

# Fraction of "spoof" bucket samples sourced from real RBA account-takeover
# ground truth rather than the synthetic CIC-IDS2018+WiFi-offset injection.
RBA_SPOOF_PCT = float(os.getenv("SIM_RBA_SPOOF_PCT", "0.5"))

# Of the remaining (non-RBA) "spoof" bucket samples, fraction sourced from a
# real native credential-stuffing row rather than a synthetic injection.
CREDENTIAL_NATIVE_PCT = float(os.getenv("SIM_CREDENTIAL_NATIVE_PCT", "0.3"))

# Fixes session sampling, signal presence, and scenario injection for reproducibility.
SIM_RANDOM_SEED = int(os.getenv("SIM_RANDOM_SEED", "20260720"))
random.seed(SIM_RANDOM_SEED)

# The CIC-IDS2018 per-flow columns the trained classifiers
# (scripts/train_dos_eop_classifiers.py) were fit on — must match that
# script's EXCLUDE/ARTIFACT_PRONE sets exactly.
NETWORK_FLOW_FEATURES = [
    "Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Fwd Pkt Len Max", "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean", "Fwd Pkt Len Std", "Bwd Pkt Len Max", "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean", "Bwd Pkt Len Std", "Flow Byts/s", "Flow Pkts/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Pkts/s", "Bwd Pkts/s", "Pkt Len Min", "Pkt Len Max", "Pkt Len Mean",
    "Pkt Len Std", "Pkt Len Var", "FIN Flag Cnt", "SYN Flag Cnt",
    "RST Flag Cnt", "PSH Flag Cnt", "ACK Flag Cnt", "URG Flag Cnt",
    "CWE Flag Count", "ECE Flag Cnt", "Down/Up Ratio", "Pkt Size Avg",
    "Fwd Seg Size Avg", "Bwd Seg Size Avg", "Fwd Byts/b Avg", "Fwd Pkts/b Avg",
    "Fwd Blk Rate Avg", "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg",
    "Subflow Fwd Pkts", "Subflow Fwd Byts", "Subflow Bwd Pkts",
    "Subflow Bwd Byts", "Fwd Act Data Pkts", "Active Mean", "Active Std",
    "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

class EnhancedSimulator:
    """Enhanced simulator matching original sim.py logic with baseline comparison"""

    def __init__(self):
        self.wifi_pool = []
        self.tls_pool = []
        self.dev_pool = []
        self.cic2018_rows = []
        self.native_pools = {}
        self.benign_rows = []
        self.rba_attack_rows = []
        self.rba_benign_rows = []
        self.stride_buckets = []
        self.engine = None
        self._init_database()
        self._load_data()
        self._load_rba_data()
        self._setup_stride_buckets()

    def _init_database(self):
        """Initialize database connection using validation service pattern"""
        self.engine = self._get_engine()

    def _get_engine(self):
        """Get database engine using validation service pattern"""
        if self.engine is not None:
            return self.engine

        dsn = DB_DSN.strip()
        if not dsn:
            print("[DB] DB_DSN missing; skipping persistence")
            return None
            
        if dsn.startswith("postgresql://"):
            dsn = "postgresql+psycopg://" + dsn[len("postgresql://"):]
        elif dsn.startswith("postgres://"):
            dsn = "postgresql+psycopg://" + dsn[len("postgres://"):]

        # Ensure SSL for remote connections
        if "localhost" not in dsn and "127.0.0.1" not in dsn and "sslmode=" not in dsn:
            dsn += ("&" if "?" in dsn else "?") + "sslmode=require"

        try:
            engine = create_engine(dsn, pool_pre_ping=True, future=True,
                                    pool_size=3, max_overflow=3,
                                    connect_args={"prepare_threshold": None})
            conns = []
            try:
                for _ in range(3):
                    c = engine.connect()
                    c.execute(text("SELECT 1"))
                    conns.append(c)
            finally:
                for c in conns:
                    c.close()
            print(f"[DB] Database engine created successfully (pool pre-warmed)")
            self.engine = engine
            return engine
        except Exception as e:
            print(f"[DB] Failed to create database engine: {e}")
            print("[DB] Continuing without database persistence")
            return None

    def _read_csv(self, path):
        """Read CSV file"""
        try:
            with open(path, newline="") as f:
                return list(csv.DictReader(f))
        except Exception as e:
            print(f"[DATA] Failed to read {path}: {e}")
            return []

    def _read_tls_csv(self, path):
        """ja3_fingerprints.csv's "ja3" field is itself comma-separated and
        unquoted, so a plain csv.DictReader against the 2-column "ja3,tag"
        header truncates every row to its first two raw fields and collides
        every entry on "771". Parse by hand: last comma-separated field is
        the real tag, everything before it (rejoined) is the real ja3 string
        — matches services/validation/app/enrichment.py's _load_tls."""
        try:
            with open(path) as f:
                lines = [ln.rstrip("\n") for ln in f if ln.strip()]
        except Exception as e:
            print(f"[DATA] Failed to read {path}: {e}")
            return []
        rows = []
        for line in lines[1:]:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 2: continue
            ja3, tag = ",".join(parts[:-1]), parts[-1]
            if ja3: rows.append({"ja3": ja3, "tag": tag})
        return rows

    def _list_csvs(self, dirpath):
        """List all CSV files in directory"""
        try:
            return [os.path.join(dirpath, f) for f in sorted(os.listdir(dirpath)) if f.endswith(".csv")]
        except Exception:
            return []

    @staticmethod
    def _reservoir_add(pool, row, seen, limit):
        """Keep an unbiased, bounded sample from a streaming population."""
        if len(pool) < limit:
            pool.append(row)
            return
        replacement = random.randrange(seen)
        if replacement < limit:
            pool[replacement] = row

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
            self.tls_pool = self._read_tls_csv(TLS_CSV)
            print(f"[DATA] Loaded {len(self.tls_pool)} TLS samples")
        except Exception as e:
            print(f"[DATA] Failed to load TLS data: {e}")

        # Load device pool
        try:
            self.dev_pool = self._read_csv(DEVICE_CSV) or [{}]
            print(f"[DATA] Loaded {len(self.dev_pool)} device samples")
        except Exception as e:
            print(f"[DATA] Failed to load device data: {e}")

        # Load CIC-IDS2018 data, categorized by each row's real label — never
        # relabeled to match whichever bucket it was drawn for. Native
        # categories map onto the dataset's attack-campaign days (02-14
        # Bruteforce, 02-15 DoS, 02-22 Web-Attack/SQLi/XSS, 02-28
        # Infiltration); classified by label text so it stays correct if more
        # days are added later.
        cic_files = self._list_csvs(CIC2018_DIR)
        if not cic_files:
            print(f"[DATA] No CIC-IDS2018 files in {CIC2018_DIR}")
            return

        self.native_pools: Dict[str, list] = {
            "dos_native": [], "eop_native": [], "exfil_native": [], "credential_native": [], "other_native": [],
        }
        benign_rows = []
        category_seen = {name: 0 for name in self.native_pools}
        benign_seen = 0
        benign_limit = MAX_PER_FILE * max(1, len(cic_files))
        for f in cic_files:
            try:
                # For files a classifier was trained on, only draw from the
                # "test" split (scripts/simulator/data_split.py) so no row a
                # model trained/tuned on can leak into live evaluation.
                restrict = is_split_file(f)
                with open(f, newline="") as handle:
                    for row_index, x in enumerate(csv.DictReader(handle)):
                        if restrict and split_bucket(row_index) != "test":
                            continue
                        lab = (x.get("Label") or x.get(" Label") or "").strip().upper()
                        if not lab or lab == "LABEL":
                            continue
                        if lab == "BENIGN":
                            if random.random() < BENIGN_KEEP:
                                benign_seen += 1
                                self._reservoir_add(benign_rows, x, benign_seen, benign_limit)
                            continue
                        cat = self._classify_native_label(lab)
                        category_seen[cat] += 1
                        self._reservoir_add(
                            self.native_pools[cat], x, category_seen[cat], MAX_PER_FILE
                        )
            except Exception as e:
                print(f"[DATA] Failed to process {f}: {e}")

        random.shuffle(benign_rows)
        self.benign_rows = benign_rows
        for cat, pool in self.native_pools.items():
            print(f"[DATA] Loaded {len(pool)} native '{cat}' samples (real label, unmodified)")
        print(f"[DATA] Loaded {len(self.benign_rows)} real Benign samples")

        # Kept for other scripts that need a generic pool of real rows to sample from.
        self.cic2018_rows = [x for pool in self.native_pools.values() for x in pool] + benign_rows
        random.shuffle(self.cic2018_rows)
        print(f"[DATA] Loaded {len(self.cic2018_rows)} CIC-IDS2018 samples total")

    @staticmethod
    def _classify_native_label(lab: str) -> str:
        """Maps a real CIC-IDS2018 label to this simulator's native pool —
        decides which pool a row is stored in, never changes the label itself."""
        if "DOS" in lab or "DDOS" in lab:
            return "dos_native"
        if "SQL INJECTION" in lab or "WEB" in lab or "XSS" in lab:
            return "eop_native"
        if "INFIL" in lab or "BOT" in lab:
            return "exfil_native"
        if "BRUTEFORCE" in lab or "BRUTE FORCE" in lab:
            return "credential_native"
        return "other_native"

    def _load_rba_data(self):
        """Load the RBA (Risk-Based Authentication) stream-sampled subset —
        real 'Is Attack IP' / 'Is Account Takeover' ground truth for the
        Spoofing STRIDE bucket, replacing the synthetic CIC-IDS2018+WiFi-offset
        injection with genuine credential-stuffing/account-takeover events from
        Wiefling et al.'s real-world login dataset. See
        updated/reference_material/citations_rba_dataset.md. Falls back to the
        synthetic method (see _make_spoofing) if the sample file isn't present —
        this is a supplementary signal source, not a hard dependency.
        """
        if not os.path.isfile(RBA_CSV):
            print(f"[DATA] No RBA sample at {RBA_CSV}; spoof bucket uses CIC-IDS2018 GPS-offset injection")
            return
        rows = self._read_csv(RBA_CSV)
        for r in rows:
            is_attack = r.get("Is Attack IP") == "True" or r.get("Is Account Takeover") == "True"
            (self.rba_attack_rows if is_attack else self.rba_benign_rows).append(r)
        print(f"[DATA] Loaded RBA sample: {len(self.rba_attack_rows)} attack rows, {len(self.rba_benign_rows)} benign rows")

    def _make_spoofing_from_rba(self, sig):
        """Real ground-truth spoofing signal, built from an RBA dataset row
        flagged Is Attack IP / Is Account Takeover — an actual credential-
        stuffing/account-takeover event rather than a synthetic GPS offset.
        Only Country-level geolocation is available in the public RBA release
        (Region/City are redacted), so GPS is approximated via a country
        centroid with a small jitter.

        Also attaches a "home"-cluster WiFi AP (the account's normal network)
        alongside the RBA-derived GPS — without this, the validation layer's
        GPS-vs-WiFi distance check (the actual mechanism that flags Spoofing;
        see services/validation/app/main.py's ip_wifi_distance_km check) would
        have nothing to compare against and could never detect these sessions,
        silently making this "harder" ground truth undetectable by construction
        rather than a genuine test of the framework."""
        row = random.choice(self.rba_attack_rows)
        country = (row.get("Country") or "").strip().upper()
        base_lat, base_lon = COUNTRY_CENTROIDS.get(country, (0.0, 0.0))
        sig["gps"] = {
            "lat": base_lat + random.uniform(-0.3, 0.3),
            "lon": base_lon + random.uniform(-0.3, 0.3),
        }
        home_ap = self._pick_wifi_row(force_foreign=False)
        if home_ap:
            bssid = home_ap.get("bssid") or home_ap.get("BSSID")
            if bssid:
                sig["wifi_bssid"] = {"bssid": str(bssid).lower()}
        ip = row.get("IP Address")
        if ip:
            sig["ip_geo"] = {"ip": ip, "country": country}
        device_type = (row.get("Device Type") or "unknown").strip().lower()
        # RBA has no patch/EDR signal — not fabricating one; device_posture here
        # only carries what RBA actually provides (device type, pseudonymous ID).
        sig["device_posture"] = {
            "device_id": f"rba-{row.get('User ID', 'unknown')}",
            "device_type": device_type,
        }

    def _setup_stride_buckets(self):
        """Setup STRIDE buckets (matching original logic)"""
        buckets = [("spoof", P_SPOOF), ("tls", P_TLS), ("dos", P_DOS),
                  ("exfil", P_EXFIL), ("eop", P_EOP), ("rep", P_REP),
                  ("benign", P_BENIGN)]
        total = sum(p for _, p in buckets) or 1.0
        cum = []
        acc = 0.0
        for k, p in buckets:
            acc += p / total
            cum.append((acc, k))
        self.stride_buckets = cum

    def _get_src_ip(self, row: Dict[str, Any]) -> Optional[str]:
        """Extract source IP from CIC-IDS2018 row"""
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

    def _pick_tls_row(self, pool, bad_only=False, clean_only=False):
        """Pick TLS row with weighting (matching original logic)"""
        if not pool:
            return None

        badtags = {"tor_suspect", "malware_family_x", "scanner_tool",
                  "cloud_proxy", "old_openssl", "insecure_client", "honeypot_fingerprint"}

        if bad_only:
            bad = [r for r in pool if (r.get("tag") or r.get("Tag") or "").strip().lower() in badtags]
            return random.choice(bad) if bad else None

        if clean_only:
            clean = [r for r in pool if (r.get("tag") or r.get("Tag") or "").strip().lower() not in badtags]
            return random.choice(clean) if clean else None

        weights = []
        for r in pool:
            tag = (r.get("tag") or r.get("Tag") or "").strip().lower()
            weights.append(0.2 if tag in badtags else 1.0)

        try:
            return random.choices(pool, weights=weights, k=1)[0]
        except:
            return random.choice(pool)

    def _pick_wifi_row(self, force_foreign: bool = False):
        """Pick a WiFi AP, weighting toward the user's known home cluster for
        normal traffic so location_risk carries real signal (see HOME_BSSIDS)."""
        if not self.wifi_pool:
            return None

        home = [r for r in self.wifi_pool if str(r.get("bssid") or r.get("BSSID") or "").lower() in HOME_BSSIDS]
        foreign = [r for r in self.wifi_pool if str(r.get("bssid") or r.get("BSSID") or "").lower() not in HOME_BSSIDS]

        if force_foreign:
            return random.choice(foreign) if foreign else random.choice(self.wifi_pool)

        if home and random.random() < HOME_BSSID_PCT:
            return random.choice(home)
        return random.choice(self.wifi_pool)

    def _ensure_floors(self, sig):
        """Ensure minimum data presence (matching original logic)"""
        # ip_geo
        if "ip_geo" not in sig:
            sig["ip_geo"] = {"ip": f"192.0.2.{random.randint(1, 254)}"}

        # wifi + gps — guarded on "gps" too so it never clobbers a GPS already
        # set by another source (e.g. _make_spoofing_from_rba's country centroid).
        if "wifi_bssid" not in sig and "gps" not in sig and self.wifi_pool:
            w = self._pick_wifi_row(force_foreign=False)
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

        # device — deliberately not backfilled here. run_simulation()'s dev_row
        # selection (gated on MIN_DEVICE) is the sole decision on whether a
        # session has a device signal at all.

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
        # uuid4 so collisions are basically impossible — everything downstream joins on session_id.
        sig["session_id"] = f"sess-{uuid.uuid4().hex[:12]}"

        # Label from CIC-IDS2018
        lab = row.get("Label") or row.get(" Label") or row.get("LABEL")
        if lab:
            sig["label"] = str(lab).strip()

        # IP from CIC-IDS2018
        src_ip = self._get_src_ip(row)
        if src_ip:
            sig["ip_geo"] = {"ip": src_ip}

        # Real per-flow network telemetry (not the Label column) — what the
        # trained classifiers score on. Gated on "Flow Duration" so
        # RBA-derived rows (no flow columns) don't get an all-zero dict.
        if row.get("Flow Duration") not in (None, ""):
            nf = {}
            for feat in NETWORK_FLOW_FEATURES:
                v = row.get(feat)
                try:
                    fv = float(v)
                    if fv != fv or fv in (float("inf"), float("-inf")):  # NaN/inf guard
                        fv = 0.0
                except (TypeError, ValueError):
                    fv = 0.0
                nf[feat] = fv
            sig["network_flow"] = nf

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
                # edr status is present in device_posture.csv ("ok"/"missing"/"outdated"/"none")
                edr_raw = str(dev_row.get("edr", "ok")).strip().lower()
                edr_ok = edr_raw == "ok"
                sig["device_posture"] = {"device_id": str(dev_id), "patched": patched, "edr": edr_ok}

        # TLS data
        if tls_row:
            ja3 = tls_row.get("ja3") or tls_row.get("JA3")
            if ja3:
                sig["tls_fp"] = {"ja3": str(ja3)}

        return sig

    def _apply_stride_scenario(self, sig, bucket):
        """Apply STRIDE scenario to signal (matching original logic)"""
        if bucket == "spoof":
            # Mix real RBA-sourced account-takeover ground truth with the
            # synthetic CIC-IDS2018+WiFi-offset injection.
            if self.rba_attack_rows and random.random() < RBA_SPOOF_PCT:
                self._make_spoofing_from_rba(sig)
                sig["label"] = "SPOOFING_INJECTED_RBA"
            else:
                self._make_spoofing(sig)
                sig["label"] = "SPOOFING_INJECTED"

        elif bucket == "tls":
            bad = self._pick_tls_row(self.tls_pool, bad_only=True)
            if bad and bad.get("ja3"):
                sig["tls_fp"] = {"ja3": bad.get("ja3")}
                sig["label"] = "HEARTBLEED"
            else:
                sig["label"] = "HEARTBLEED"

        elif bucket == "exfil":
            # Observable, session-level Information Disclosure scenario — the
            # evidence a DLP/network-monitoring integration would expose.
            baseline = random.randint(400_000, 1_200_000)
            outbound = baseline * random.randint(25, 80)
            sig["exfiltration_telemetry"] = {
                "outbound_bytes": outbound,
                "baseline_outbound_bytes": baseline,
                "destination_is_new": True,
                "sensitive_data_accessed": True,
                "dlp_alert": True,
                "connections_last_5m": random.randint(20, 80),
            }
            sig["label"] = "EXFILTRATION_INJECTED"

        # "dos"/"eop" don't land here: run_simulation() sources those buckets
        # from real, correctly-labelled native rows directly.

        elif bucket == "rep":
            sig["label"] = "REPUDIATION_INJECTED"
            sig["repudiation"] = True

        elif bucket == "benign":
            # No scenario applied — the real CIC-IDS2018 label from
            # _mk_signals is left untouched.
            pass

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
        """Call ablation framework"""
        try:
            start_time = time.perf_counter()

            print(f"[ABLATION] Calling ablation for {sig['session_id']}")
            response = await client.post(ABLATION_URL, json={"signals": sig}, timeout=30.0)
            response.raise_for_status()
            decision = response.json()

            end_time = time.perf_counter()
            processing_time_ms = int((end_time - start_time) * 1000)

            decision_val = decision.get("decision", "unknown")
            risk_score = decision.get("risk_score", 0.0)
            enforcement = decision.get("enforcement", "ALLOW")
            factors = decision.get("factors", [])

            print(f"[ABLATION] Decision for {sig['session_id']}: {decision_val} (risk={risk_score}, factors={factors})")

            return {
                "framework": "ablation",
                "session_id": sig["session_id"],
                "decision": decision_val,
                "risk_score": risk_score,
                "enforcement": enforcement,
                "factors": factors,
                "processing_time_ms": processing_time_ms,
                "full_response": decision
            }
        except httpx.HTTPStatusError as e:
            print(f"[ABLATION] HTTP Error for {sig['session_id']}: {e.response.status_code} - {e.response.text}")
            return None
        except httpx.TimeoutException as e:
            print(f"[ABLATION] Timeout for {sig['session_id']}: {e}")
            return None
        except Exception as e:
            print(f"[ABLATION] Unexpected error for {sig['session_id']}: {e}")
            return None

    async def _call_generic_baseline(self, client, sig, url: str, tag: str):
        """Generic caller for published baseline services (Ahmadi, Jimmy, Phani)."""
        try:
            start_time = time.perf_counter()
            response = await client.post(url, json={"signals": sig}, timeout=30.0)
            response.raise_for_status()
            decision = response.json()
            processing_time_ms = int((time.perf_counter() - start_time) * 1000)
            decision_val = decision.get("decision", "unknown")
            risk_score   = decision.get("risk_score", 0.0)
            enforcement  = decision.get("enforcement", "ALLOW")
            factors      = decision.get("factors", {})
            print(f"[{tag.upper()}] {sig['session_id']}: {decision_val} (risk={risk_score:.3f})")
            return {
                "framework":          tag,
                "session_id":         sig["session_id"],
                "decision":           decision_val,
                "risk_score":         risk_score,
                "enforcement":        enforcement,
                "factors":            factors,
                "processing_time_ms": processing_time_ms,
                "full_response":      decision,
            }
        except Exception as e:
            print(f"[{tag.upper()}] Error for {sig['session_id']}: {e}")
            return None

    def _store_comparison_data(self, comparison_id: str, proposed_result: Optional[Dict[str, Any]] = None,
                              baseline_result: Optional[Dict[str, Any]] = None, signal: Optional[Dict[str, Any]] = None,
                              extra_results: Optional[list] = None):
        """Store comparison data in database using validation service pattern.

        Batches all frameworks' rows into 2 multi-row INSERTs (executemany) instead
        of up to 8 individual round trips — each round trip to the remote DB costs
        real network time even on an already-warm connection, so batching keeps
        per-sample DB overhead low."""
        eng = self._get_engine()
        if eng is None:
            return

        all_results = [proposed_result, baseline_result] + (extra_results or [])
        valid_results = [r for r in all_results if r and isinstance(r, dict)
                          and r.get("framework") and r.get("decision") != "unknown"]
        if not valid_results:
            return

        comparison_rows = [{
            "comp_id": comparison_id,
            "framework": r["framework"],
            "session_id": r["session_id"],
            "decision": r["decision"],
            "risk_score": float(r.get("risk_score", 0.0)),
            "enforcement": r.get("enforcement", "ALLOW"),
            "factors": json.dumps(r.get("factors", [])),
            "processing_time": r.get("processing_time_ms", 0)
        } for r in valid_results]

        classification_rows = []
        if signal:
            ground_truth = signal.get("label", "BENIGN")
            is_malicious_actual = ground_truth.upper() != "BENIGN"
            for r in valid_results:
                predicted_threats = r.get("factors", []) if isinstance(r.get("factors"), list) else []
                # Ground truth vs. the framework's actual enforcement decision
                # (consistent across all frameworks: allow/step_up/deny).
                has_threats_predicted = r.get("decision") in ("step_up", "deny")
                classification_rows.append({
                    "session_id": r["session_id"],
                    "original_label": ground_truth,
                    "predicted_threats": json.dumps(predicted_threats),
                    "framework": r["framework"],
                    "false_positive": not is_malicious_actual and has_threats_predicted,
                    "false_negative": is_malicious_actual and not has_threats_predicted
                })

        try:
            with eng.begin() as conn:
                conn.execute(text("""
                    INSERT INTO zta.framework_comparison
                    (comparison_id, framework_type, session_id, decision, risk_score,
                     enforcement, factors, processing_time_ms)
                    VALUES (:comp_id, :framework, :session_id, :decision, :risk_score,
                            :enforcement, :factors, :processing_time)
                """), comparison_rows)

                if classification_rows:
                    conn.execute(text("""
                        INSERT INTO zta.security_classifications
                        (session_id, original_label, predicted_threats, framework_type,
                         false_positive, false_negative)
                        VALUES (:session_id, :original_label, :predicted_threats, :framework,
                                :false_positive, :false_negative)
                    """), classification_rows)

            for r in valid_results:
                print(f"[DB] Stored {r['framework']} framework data: {r['decision']}")
        except Exception as e:
            print(f"[DB] Failed to store comparison data: {e}")

    async def run_simulation(self, max_samples: Optional[int] = None, sleep_time: Optional[float] = None):
        """Run enhanced simulation with STRIDE scenarios"""
        if max_samples is None:
            max_samples = MAX_ROWS
        if sleep_time is None:
            sleep_time = SLEEP_BETWEEN

        # Initialize data if not already done
        if not hasattr(self, 'cic2018_rows') or not self.cic2018_rows:
            self._load_data()

        if not self.cic2018_rows:
            print("[SIM] No CIC-IDS2018 data available")
            return {"comparison_id": None, "total_samples": 0, "successful_comparisons": 0}

        print(f"[SIM] pools: wifi={len(self.wifi_pool)} tls={len(self.tls_pool)} device={len(self.dev_pool)}")
        print(f"[SIM] Starting enhanced simulation with {max_samples} samples")
        print(f"[SIM] Proposed   : {VALIDATE_URL} -> {GATEWAY_URL}")
        print(f"[SIM] Ablation   : {ABLATION_URL}")
        print(f"[SIM] Ahmadi2025 : {AHMADI_URL}")
        print(f"[SIM] Jimmy2025  : {JIMMY_URL}")
        print(f"[SIM] Phani2025  : {PHANI_URL}")

        comparison_id = os.getenv("SIM_COMPARISON_ID") or f"comp-{uuid.uuid4().hex}"
        sent = 0
        successful_comparisons = 0

        async with httpx.AsyncClient(timeout=60.0) as client:
            while sent < max_samples:
                try:
                    # Assign STRIDE bucket first, then pick the row it needs. A "dos"
                    # bucket pulls from real DoS-labelled rows and reports their real
                    # label; only bucket="spoof"/"tls"/"rep" construct a synthetic
                    # scenario on top of a genuinely Benign row, since CIC-IDS2018 has
                    # no native representation for those three categories.
                    r = random.random()
                    bucket = "spoof"
                    for edge, k in self.stride_buckets:
                        if r <= edge:
                            bucket = k
                            break

                    row = None
                    native_passthrough = False
                    force_foreign = False

                    if bucket in ("dos", "eop") or (bucket == "exfil" and EXFIL_MODE == "native"):
                        pool_name = {"dos": "dos_native", "exfil": "exfil_native", "eop": "eop_native"}[bucket]
                        pool = self.native_pools.get(pool_name) or []
                        if pool:
                            row = random.choice(pool)
                            native_passthrough = True
                        else:
                            # No real rows in this category — fall back to a
                            # benign pass-through instead of inventing a label.
                            bucket = "benign"

                    elif bucket == "spoof" and self.native_pools.get("credential_native") and random.random() < CREDENTIAL_NATIVE_PCT:
                        # A real credential-stuffing attack is itself a legitimate
                        # Spoofing-adjacent case — pass it through under its own real label.
                        row = random.choice(self.native_pools["credential_native"])
                        native_passthrough = True

                    if row is None:
                        row = random.choice(self.benign_rows) if self.benign_rows else None
                        force_foreign = (bucket == "spoof")

                    if row is None:
                        print("[SIM] No rows available (native pools and benign pool both empty), stopping")
                        break

                    # Select data sources (matching original logic)
                    wifi_row = self._pick_wifi_row(force_foreign=force_foreign)
                    # Keep the negative class internally consistent: critical
                    # JA3 fingerprints are assigned only by the TLS scenario.
                    tls_row = self._pick_tls_row(self.tls_pool, clean_only=True) if self.tls_pool else None
                    # Withholding a device row for (1 - MIN_DEVICE) of sessions is
                    # independent of ground truth — a genuine "unrecognized device"
                    # case, not a label-correlated signal.
                    dev_row = random.choice(self.dev_pool) if self.dev_pool and random.random() < MIN_DEVICE else None

                    # Create base signal
                    sig = self._mk_signals(row, wifi_row, tls_row, dev_row)

                    # Apply STRIDE scenario — skipped entirely for a native pass-through,
                    # whose real label (set by _mk_signals from `row` above) must not be touched.
                    if not native_passthrough:
                        self._apply_stride_scenario(sig, bucket)

                    # Ensure minimum data presence
                    self._ensure_floors(sig)

                    tag = f"{bucket}, native" if native_passthrough else bucket
                    print(f"[SIM] Processing sample {sent+1}/{max_samples} - {sig['session_id']} (bucket: {tag})")

                    # Jimmy (2025) excluded — no published risk-scoring formula to reproduce.
                    results = await asyncio.gather(
                        self._call_proposed_framework(client, sig),
                        self._call_baseline_framework(client, sig),
                        self._call_generic_baseline(client, sig, AHMADI_URL, "ahmadi2025"),
                        self._call_generic_baseline(client, sig, PHANI_URL,  "phani2025"),
                        return_exceptions=True
                    )

                    proposed_result: Optional[Dict[str, Any]] = None
                    baseline_result: Optional[Dict[str, Any]] = None
                    extra_results: list = []

                    # Handle exceptions and type-safe assignment
                    labels = ["proposed", "ablation", "ahmadi2025", "phani2025"]
                    for i, (label, res) in enumerate(zip(labels, results)):
                        if isinstance(res, Exception):
                            print(f"[SIM] {label} error: {res}")
                        elif isinstance(res, dict):
                            if i == 0:
                                proposed_result = res
                            elif i == 1:
                                baseline_result = res
                            else:
                                extra_results.append(res)

                    complete_pair = (
                        proposed_result is not None
                        and baseline_result is not None
                        and len(extra_results) == 2
                    )
                    if complete_pair:
                        self._store_comparison_data(comparison_id, proposed_result, baseline_result, sig, extra_results)
                        successful_comparisons += 1
                        for label, res in zip(labels, results):
                            if isinstance(res, dict):
                                print(f"[SIM]   {label:12s}: {res.get('decision','?'):8s} risk={res.get('risk_score',0):.3f}")
                    else:
                        print(f"[SIM]   Incomplete framework quartet for {sig.get('session_id', 'unknown')}; not persisted")

                    # Sleep between requests
                    await asyncio.sleep(sleep_time)
                    sent += 1

                except KeyboardInterrupt:
                    print("[SIM] Simulation interrupted by user")
                    break
                except Exception as e:
                    print(f"[SIM] Unexpected error for sample {sent+1}: {e}")
                    sent += 1
                    continue

        print("[SIM] Simulation completed!")
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
