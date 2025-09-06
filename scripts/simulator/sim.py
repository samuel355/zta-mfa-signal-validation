#!/usr/bin/env python3
# dataset-only, multi-file, randomized per-session

import os, sys, csv, json, random, time, math
from typing import Dict, Any, List, Optional
import httpx

# -----------------------------
# Paths & service endpoints
# -----------------------------
DATA_DIR      = os.getenv("DATA_DIR", "/app/data")
CICIDS_DIR    = os.getenv("CICIDS_DIR", f"{DATA_DIR}/cicids")
WIFI_CSV      = os.getenv("WIFI_CSV",  f"{DATA_DIR}/wifi/wigle_sample.csv")
DEVICE_CSV    = os.getenv("DEVICE_CSV",f"{DATA_DIR}/device_posture/device_posture.csv")
TLS_CSV       = os.getenv("TLS_CSV",   f"{DATA_DIR}/tls/ja3_fingerprints.csv")

VALIDATE_URL  = os.getenv("VALIDATE_URL", "http://validation:8000/validate")
GATEWAY_URL   = os.getenv("GATEWAY_URL",  "http://gateway:8000/decision")

SLEEP_BETWEEN = float(os.getenv("SIM_SLEEP", "0.8"))
MAX_ROWS      = int(os.getenv("SIM_MAX_ROWS", "300"))
USE_GPS_FROM_WIFI = os.getenv("SIM_USE_GPS_FROM_WIFI", "false").lower() in {"1","true","yes","on"}

# -----------------------------
# Class balance knobs
# -----------------------------
BENIGN_KEEP_RATE = float(os.getenv("SIM_BENIGN_KEEP", "0.15"))  # keep 15% of benign
MAX_PER_FILE     = int(os.getenv("SIM_MAX_PER_FILE", "500"))    # cap per CICIDS CSV after filtering
ATTACK_ONLY      = os.getenv("SIM_ATTACK_ONLY", "false").lower() in {"1","true","yes","on"}
ATTACK_WHITELIST = {s.strip().upper() for s in os.getenv("SIM_ATTACK_WHITELIST", "").split(",") if s.strip()}

# -----------------------------
# Realism knobs
# -----------------------------
INJECT_GPS_MISMATCH = float(os.getenv("SIM_INJECT_GPS_MISMATCH", "0.30"))  # 30%: GPS far from Wi-Fi
TLS_BAD_RATE        = float(os.getenv("SIM_TLS_BAD_RATE", "0.15"))         # 15%: force bad TLS tag
PATCHED_TRUE_RATE   = float(os.getenv("SIM_PATCHED_TRUE_RATE", "0.70"))    # 70%: make device patched=True
GPS_OFFSET_KM       = float(os.getenv("SIM_GPS_OFFSET_KM", "400.0"))       # how far to push mismatched GPS

# -----------------------------
# Utilities
# -----------------------------
def _label_of(row: Dict[str, Any]) -> str:
    lab = row.get("Label") or row.get(" label") or row.get("LABEL") or ""
    return str(lab).strip().upper()

def _read_csv(path: str) -> List[Dict[str, Any]]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

def _list_csvs(dirpath: str) -> List[str]:
    return [os.path.join(dirpath, f) for f in os.listdir(dirpath) if f.endswith(".csv")]

def _wifi_rows() -> List[Dict[str, Any]]:
    try:
        rows = _read_csv(WIFI_CSV)
        return [r for r in rows if (r.get("bssid") or r.get("BSSID"))]
    except Exception:
        return []

def _device_rows() -> List[Dict[str, Any]]:
    try:
        return _read_csv(DEVICE_CSV)
    except Exception:
        return []

def _tls_rows() -> List[Dict[str, Any]]:
    try:
        return _read_csv(TLS_CSV)
    except Exception:
        return []

# Prefer benign TLS; keep malicious rare
_BAD_TLS = {
    "tor_suspect","malware_family_x","scanner_tool",
    "cloud_proxy","old_openssl","insecure_client","honeypot_fingerprint"
}

def _weighted_tls_choice(rows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not rows:
        return None
    weights = []
    for r in rows:
        tag = (r.get("tag") or r.get("Tag") or "").strip().lower()
        weights.append(0.2 if tag in _BAD_TLS else 1.0)
    try:
        return random.choices(rows, weights=weights, k=1)[0]
    except Exception:
        return random.choice(rows)

def _pick_tls_row(rows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Prefer benign, but with TLS_BAD_RATE force a bad tag if available."""
    if not rows:
        return None
    if random.random() < TLS_BAD_RATE:
        bad = [r for r in rows if (r.get("tag") or r.get("Tag") or "").strip().lower() in _BAD_TLS]
        if bad:
            return random.choice(bad)
    return _weighted_tls_choice(rows)

def _offset_gps(lat: float, lon: float, km: float) -> tuple[float, float]:
    # approx: 1 deg lat ~111km; lon scaled by cos(lat)
    dlat = km / 111.0
    dlon = (km / (111.0 * max(0.1, math.cos(math.radians(lat))))) * (1 if random.random()<0.5 else -1)
    return lat + (dlat if random.random()<0.5 else -dlat), lon + dlon

# -----------------------------
# Signal construction
# -----------------------------
def _mk_signals(row: Dict[str, Any],
                wifi_row: Optional[Dict[str, Any]],
                tls_row:  Optional[Dict[str, Any]],
                dev_row:  Optional[Dict[str, Any]]) -> Dict[str, Any]:
    sig: Dict[str, Any] = {}

    # stable correlator
    sig["session_id"] = f"sess-{random.randrange(100000,999999)}"

    # label direct from CICIDS (often BENIGN)
    lab = row.get("Label") or row.get(" label") or row.get("LABEL")
    if lab is not None:
        sig["label"] = str(lab).strip()

    # IP from CICIDS row
    src_ip = row.get("Src IP") or row.get(" Source IP") or row.get("Src_IP") or row.get("src_ip")
    if src_ip:
        sig["ip_geo"] = {"ip": str(src_ip).strip()}

    # Wi-Fi + GPS (sometimes mismatched)
    if wifi_row:
        bssid = wifi_row.get("bssid") or wifi_row.get("BSSID")
        if bssid:
            sig["wifi_bssid"] = {"bssid": str(bssid).lower()}
        lat = wifi_row.get("lat") or wifi_row.get("Lat") or wifi_row.get("latitude")
        lon = wifi_row.get("lon") or wifi_row.get("Lon") or wifi_row.get("longitude")
        try:
            if lat not in (None, "") and lon not in (None, ""):
                latf, lonf = float(lat), float(lon)
                if random.random() < INJECT_GPS_MISMATCH:
                    g_lat, g_lon = _offset_gps(latf, lonf, GPS_OFFSET_KM)
                elif USE_GPS_FROM_WIFI:
                    g_lat, g_lon = latf, lonf
                else:
                    g_lat = g_lon = None
                if g_lat is not None and g_lon is not None:
                    sig["gps"] = {"lat": g_lat, "lon": g_lon}
        except Exception:
            pass

    # Device posture with patched bias
    if dev_row:
        dev_id = dev_row.get("device_id") or dev_row.get("Device_ID") or dev_row.get("deviceId")
        if dev_id:
            patched_s = str(dev_row.get("patched", "")).strip().lower()
            if patched_s in {"true","false"}:
                patched = (patched_s == "true")
            else:
                patched = True
            if random.random() < PATCHED_TRUE_RATE:
                patched = True
            sig["device_posture"] = {"device_id": str(dev_id), "patched": patched}

    # TLS JA3
    if tls_row:
        ja3 = tls_row.get("ja3") or tls_row.get("JA3")
        if ja3:
            sig["tls_fp"] = {"ja3": str(ja3)}

    return sig

# -----------------------------
# HTTP posting
# -----------------------------
def _post_validate_and_decide(client: httpx.Client, signals: Dict[str, Any]) -> Dict[str, Any]:
    try:
        vr = client.post(VALIDATE_URL, json={"signals": signals}, timeout=10.0)
        vr.raise_for_status()
        validated = vr.json().get("validated", {})
    except Exception as e:
        return {"ok": False, "stage": "validate", "error": str(e)}

    try:
        dr = client.post(GATEWAY_URL, json={"validated": validated, "siem": {}}, timeout=10.0)
        dr.raise_for_status()
        return {"ok": True, **dr.json()}
    except Exception as e:
        return {"ok": False, "stage": "decision", "error": str(e)}

# -----------------------------
# Main
# -----------------------------
def main():
    cic_files = _list_csvs(CICIDS_DIR)
    if not cic_files:
        print(f"[sim] no CICIDS CSVs in {CICIDS_DIR}")
        sys.exit(0)

    wifi_pool = _wifi_rows()
    tls_pool  = _tls_rows()
    dev_pool  = _device_rows() or [{}]

    # Balanced collection from all CICIDS CSVs
    all_rows: List[Dict[str, Any]] = []
    for f in cic_files:
        try:
            rows = _read_csv(f)
            random.shuffle(rows)

            attacks, benign = [], []
            for r in rows:
                L = _label_of(r)
                if ATTACK_ONLY:
                    if L != "BENIGN":
                        if ATTACK_WHITELIST and L not in ATTACK_WHITELIST:
                            continue
                        attacks.append(r)
                else:
                    if L == "BENIGN":
                        if random.random() < BENIGN_KEEP_RATE:
                            benign.append(r)
                    else:
                        if ATTACK_WHITELIST and L not in ATTACK_WHITELIST:
                            continue
                        attacks.append(r)

            per_file = attacks + benign
            random.shuffle(per_file)
            all_rows.extend(per_file[:MAX_PER_FILE])
        except Exception:
            pass

    random.shuffle(all_rows)

    sent = 0
    with httpx.Client() as client:
        for row in all_rows:
            wifi_row = random.choice(wifi_pool) if wifi_pool else None
            tls_row  = _pick_tls_row(tls_pool) if tls_pool else None
            dev_row  = random.choice(dev_pool) if dev_pool else None

            sig = _mk_signals(row, wifi_row, tls_row, dev_row)
            if not any(k in sig for k in ("ip_geo","wifi_bssid","tls_fp","device_posture")):
                continue

            out = _post_validate_and_decide(client, sig)
            print(json.dumps(out))

            sent += 1
            # jittered pacing so we don't burst
            time.sleep(SLEEP_BETWEEN * random.uniform(0.8, 1.3))
            if sent >= MAX_ROWS:
                break

    print("[sim] done")

if __name__ == "__main__":
    main()