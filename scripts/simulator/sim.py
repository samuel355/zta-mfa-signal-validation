#!/usr/bin/env python3
# dataset-only, multi-file, randomized per-session
import os, sys, csv, json, random, time
from typing import Dict, Any, List, Optional
import httpx

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

# --- Balancing knobs ---
BENIGN_KEEP_RATE = float(os.getenv("SIM_BENIGN_KEEP", "0.15"))
MAX_PER_FILE     = int(os.getenv("SIM_MAX_PER_FILE", "500"))
ATTACK_ONLY      = os.getenv("SIM_ATTACK_ONLY", "false").lower() in {"1","true","yes","on"}
ATTACK_WHITELIST = {s.strip().upper() for s in os.getenv("SIM_ATTACK_WHITELIST", "").split(",") if s.strip()}

# --- Realism knobs ---
MIN_WIFI   = float(os.getenv("SIM_MIN_WIFI", "0.0"))
MIN_GPS    = float(os.getenv("SIM_MIN_GPS", "0.0"))
MIN_TLS    = float(os.getenv("SIM_MIN_TLS", "0.0"))
MIN_DEVICE = float(os.getenv("SIM_MIN_DEVICE", "0.0"))
USE_GPS_FROM_WIFI = os.getenv("SIM_USE_GPS_FROM_WIFI","false").lower() in {"1","true","yes","on"}

INJECT_GPS_MISMATCH = float(os.getenv("SIM_INJECT_GPS_MISMATCH", "0.30"))
TLS_BAD_RATE        = float(os.getenv("SIM_TLS_BAD_RATE", "0.15"))
PATCHED_TRUE_RATE   = float(os.getenv("SIM_PATCHED_TRUE_RATE", "0.70"))
GPS_OFFSET_KM       = float(os.getenv("SIM_GPS_OFFSET_KM", "400.0"))

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def _to_float(x) -> Optional[float]:
    try:
        return float(str(x).strip())
    except Exception:
        return None

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

def _ensure_floors(sig, row, wifi_pool, tls_pool, dev_pool):
    # ip_geo from CICIDS
    if "ip_geo" not in sig:
        for k in ("Src IP"," Source IP","Src_IP","src_ip"):
            if row.get(k):
                sig["ip_geo"] = {"ip": str(row[k]).strip()}
                break
    # wifi_bssid (+ optional gps from Wi-Fi)
    if "wifi_bssid" not in sig and wifi_pool and random.random() < MIN_WIFI:
        w = random.choice(wifi_pool)
        b = w.get("bssid") or w.get("BSSID")
        if b:
            sig["wifi_bssid"] = {"bssid": str(b).lower()}
            if USE_GPS_FROM_WIFI and "gps" not in sig:
                lat = w.get("lat") or w.get("Lat") or w.get("latitude")
                lon = w.get("lon") or w.get("Lon") or w.get("longitude")
                try:
                    if lat not in (None,"") and lon not in (None,""):
                        sig["gps"] = {"lat": float(lat), "lon": float(lon)}
                except Exception:
                    pass
    # gps floor (if still missing but we have wifi)
    if "gps" not in sig and USE_GPS_FROM_WIFI and "wifi_bssid" in sig and random.random() < MIN_GPS:
        bssid = sig["wifi_bssid"]["bssid"]
        w = next((x for x in wifi_pool if str(x.get("bssid") or x.get("BSSID")).lower()==bssid), None)
        if w:
            lat = w.get("lat") or w.get("Lat") or w.get("latitude")
            lon = w.get("lon") or w.get("Lon") or w.get("longitude")
            try:
                sig["gps"] = {"lat": float(lat), "lon": float(lon)}
            except Exception:
                pass
    # tls_fp
    if "tls_fp" not in sig and tls_pool and random.random() < MIN_TLS:
        r = random.choice(tls_pool)
        ja3 = r.get("ja3") or r.get("JA3")
        if ja3:
            sig["tls_fp"] = {"ja3": str(ja3)}
    # device_posture
    if "device_posture" not in sig and dev_pool and random.random() < MIN_DEVICE:
        d = random.choice(dev_pool)
        dev_id = d.get("device_id") or d.get("Device_ID") or d.get("deviceId")
        if dev_id:
            patched_s = str(d.get("patched","")).strip().lower()
            patched = True if patched_s not in {"true","false"} else (patched_s=="true")
            sig["device_posture"] = {"device_id": str(dev_id), "patched": patched}
            
            
def _weighted_tls_choice(rows: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    if not rows:
        return None
    weights = []
    for r in rows:
        tag = (r.get("tag") or r.get("Tag") or "").strip().lower()
        if tag in {"tor_suspect", "malware_family_x", "scanner_tool",
                   "cloud_proxy", "old_openssl", "insecure_client", "honeypot_fingerprint"}:
            weights.append(0.2)
        else:
            weights.append(1.0)
    try:
        return random.choices(rows, weights=weights, k=1)[0]
    except Exception:
        return random.choice(rows)

def _offset_gps(lat: float, lon: float, km: float) -> tuple[float, float]:
    from math import radians, sin, cos, asin, sqrt
    R = 6371.0
    dlat = km / 111.0
    dlon = (km / (111.0 * max(0.1, cos(radians(lat))))) * (1 if random.random()<0.5 else -1)
    return lat + (dlat if random.random()<0.5 else -dlat), lon + dlon

# ------------------------------------------------------
# 
# -------------
# Scenario builders (STRIDE mapping variety)
# -------------------------------------------------------------------

def _make_spoofing(sig: Dict[str,Any], wifi_pool: List[Dict[str,Any]]):
    """Inject GPS spoofing relative to the *same* Wi-Fi BSSID when possible."""
    if "gps" in sig or "wifi_bssid" not in sig or not wifi_pool:
        return
    if random.random() >= INJECT_GPS_MISMATCH:
        return

    bssid = str(sig["wifi_bssid"].get("bssid", "")).lower()
    w = next((r for r in wifi_pool if str(r.get("bssid") or r.get("BSSID")).lower() == bssid), None)
    if not w:
        w = random.choice(wifi_pool)

    lat = _to_float(w.get("lat") or w.get("Lat") or w.get("latitude"))
    lon = _to_float(w.get("lon") or w.get("Lon") or w.get("longitude"))
    if lat is None or lon is None:
        return

    try:
        g_lat, g_lon = _offset_gps(lat, lon, GPS_OFFSET_KM)
        sig["gps"] = {"lat": g_lat, "lon": g_lon}
    except Exception:
        pass

def _make_posture(sig: Dict[str,Any], dev_pool: List[Dict[str,Any]]):
    """Device posture injection"""
    if not dev_pool:
        return
    d = random.choice(dev_pool)
    dev_id = d.get("device_id") or d.get("Device_ID") or d.get("deviceId")
    if dev_id:
        patched = str(d.get("patched", "")).strip().lower() == "true"
        if random.random() < PATCHED_TRUE_RATE:
            patched = True
        sig["device_posture"] = {"device_id": str(dev_id), "patched": patched}

def _make_tls(sig: Dict[str,Any], tls_pool: List[Dict[str,Any]]):
    """TLS fingerprint injection (rarely ‘bad’)."""
    if not tls_pool:
        return
    bad_tags = {
        "tor_suspect","malware_family_x","scanner_tool",
        "cloud_proxy","old_openssl","insecure_client","honeypot_fingerprint"
    }
    if random.random() < TLS_BAD_RATE:
        bad = [
            r for r in tls_pool
            if (r.get("tag") or r.get("Tag") or "").strip().lower() in bad_tags
        ]
        if bad:
            row = random.choice(bad)
            ja3 = row.get("ja3") or row.get("JA3")
            if ja3:
                sig["tls_fp"] = {"ja3": str(ja3)}
                return

    row = _weighted_tls_choice(tls_pool)
    if row:
        ja3 = row.get("ja3") or row.get("JA3")
        if ja3:
            sig["tls_fp"] = {"ja3": str(ja3)}

# -------------------------------------------------------------------
# Label handling from CICIDS
# -------------------------------------------------------------------

def _label_of(row: Dict[str, Any]) -> str:
    lab = row.get("Label") or row.get(" label") or row.get("LABEL") or ""
    return str(lab).strip().upper()

# -------------------------------------------------------------------
# Signals assembly
# -------------------------------------------------------------------

def _mk_signals(row: Dict[str, Any],
                wifi_row: Dict[str, Any] | None,
                tls_row:  Dict[str, Any] | None,
                dev_row:  Dict[str, Any] | None) -> Dict[str, Any]:
    sig: Dict[str, Any] = {}
    sig["session_id"] = f"sess-{random.randrange(100000,999999)}"

    # Label (from CICIDS)
    lab = row.get("Label") or row.get(" label") or row.get("LABEL")
    if lab is not None:
        sig["label"] = str(lab).strip()

    # IP
    src_ip = row.get("Src IP") or row.get(" Source IP") or row.get("Src_IP") or row.get("src_ip")
    if src_ip:
        sig["ip_geo"] = {"ip": str(src_ip).strip()}

    # Wi-Fi
    if wifi_row:
        bssid = wifi_row.get("bssid") or wifi_row.get("BSSID")
        if bssid:
            sig["wifi_bssid"] = {"bssid": str(bssid).lower()}
        lat = wifi_row.get("lat") or wifi_row.get("Lat") or wifi_row.get("latitude")
        lon = wifi_row.get("lon") or wifi_row.get("Lon") or wifi_row.get("longitude")
        latf, lonf = _to_float(lat), _to_float(lon)
        if latf is not None and lonf is not None and USE_GPS_FROM_WIFI:
            sig["gps"] = {"lat": latf, "lon": lonf}

    # Device posture
    if dev_row:
        _make_posture(sig, [dev_row])

    # TLS
    if tls_row:
        _make_tls(sig, [tls_row])

    return sig

# -------------------------------------------------------------------
# HTTP calls
# -------------------------------------------------------------------

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

# -------------------------------------------------------------------
# Main loop
# -------------------------------------------------------------------

def main():
    cic_files = _list_csvs(CICIDS_DIR)
    if not cic_files:
        print(f"[sim] no CICIDS CSVs in {CICIDS_DIR}")
        sys.exit(0)

    wifi_pool = _wifi_rows()
    tls_pool  = _tls_rows()
    dev_pool  = _device_rows() or [{}]

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
            tls_row  = _weighted_tls_choice(tls_pool) if tls_pool else None
            dev_row  = random.choice(dev_pool) if dev_pool else None

            sig = _mk_signals(row, wifi_row, tls_row, dev_row)
            _ensure_floors(sig, row, wifi_pool, tls_pool, dev_pool)
            _make_spoofing(sig, wifi_pool)

            if not any(k in sig for k in ("ip_geo","wifi_bssid","tls_fp","device_posture")):
                continue

            try:
                out = _post_validate_and_decide(client, sig)
                print(json.dumps(out))
                time.sleep(SLEEP_BETWEEN * random.uniform(0.8, 1.3))
            except Exception as e:
                print(json.dumps({"ok": False, "error": str(e)}))

            sent += 1
            if sent >= MAX_ROWS:
                break

    print("[sim] done")

if __name__ == "__main__":
    main()