#!/usr/bin/env python3
# scripts/simulator/sim.py  (dataset-only, multi-file)
import os, sys, csv, json, random, time
import httpx
from typing import Dict, Any, List

DATA_DIR      = os.getenv("DATA_DIR", "/app/data")
CICIDS_DIR    = os.getenv("CICIDS_DIR", f"{DATA_DIR}/cicids")
WIFI_CSV      = os.getenv("WIFI_CSV",  f"{DATA_DIR}/wifi/wigle_sample.csv")
DEVICE_CSV    = os.getenv("DEVICE_CSV",f"{DATA_DIR}/device_posture/device_posture.csv")
TLS_CSV       = os.getenv("TLS_CSV",   f"{DATA_DIR}/tls/ja3_fingerprints.csv")

VALIDATE_URL  = os.getenv("VALIDATE_URL", "http://validation:8000/validate")
GATEWAY_URL   = os.getenv("GATEWAY_URL",  "http://gateway:8000/decision")

SLEEP_BETWEEN = float(os.getenv("SIM_SLEEP", "0.8"))
MAX_ROWS      = int(os.getenv("SIM_MAX_ROWS", "200"))

def _read_csv(path: str) -> List[Dict[str, Any]]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

def _list_csvs(dirpath: str) -> List[str]:
    return [os.path.join(dirpath, f) for f in os.listdir(dirpath) if f.endswith(".csv")]

def _wifi() -> Dict[str, Any]:
    try:
        rows = _read_csv(WIFI_CSV)
        return rows[0] if rows else {}
    except Exception:
        return {}

def _devices() -> List[Dict[str, Any]]:
    try:
        return _read_csv(DEVICE_CSV)
    except Exception:
        return []

def _tls() -> List[Dict[str, Any]]:
    try:
        return _read_csv(TLS_CSV)
    except Exception:
        return []

def _mk_signals(row: Dict[str, Any], wifi: Dict[str, Any], tls_rows: List[Dict[str, Any]], dev: Dict[str, Any]) -> Dict[str, Any]:
    sig: Dict[str, Any] = {}
    # session id (correlator)
    sig["session_id"] = f"sess-{random.randrange(100000,999999)}"
    # label (whatever is in dataset; may be BENIGN)
    if row.get("Label") is not None:
        sig["label"] = row["Label"]

    # IP
    src_ip = row.get("Src IP") or row.get(" Source IP") or row.get("Src_IP")
    if src_ip:
        sig["ip_geo"] = {"ip": src_ip}

    # Wi-Fi / GPS from wifi sample (only if lat/lon present; never fabricate)
    lat = wifi.get("lat") or wifi.get("Lat") or wifi.get("latitude")
    lon = wifi.get("lon") or wifi.get("Lon") or wifi.get("longitude")
    if lat not in (None, "") and lon not in (None, ""):
        try:
            sig["gps"] = {"lat": float(lat), "lon": float(lon)}
        except Exception:
            pass
    bssid = wifi.get("bssid") or wifi.get("BSSID")
    if bssid:
        sig["wifi_bssid"] = {"bssid": str(bssid).lower()}

    # Device posture
    dev_id = dev.get("device_id") or dev.get("Device_ID") or dev.get("deviceId")
    if dev_id:
        sig["device_posture"] = {"device_id": dev_id}

    # TLS JA3
    if tls_rows:
        pick = random.choice(tls_rows)
        ja3 = pick.get("ja3") or pick.get("JA3")
        if ja3:
            sig["tls_fp"] = {"ja3": ja3}

    return sig

def _post_validate_and_decide(client: httpx.Client, signals: Dict[str, Any]) -> Dict[str, Any]:
    vr = client.post(VALIDATE_URL, json={"signals": signals}, timeout=10.0)
    vr.raise_for_status()
    validated = vr.json().get("validated", {})

    dr = client.post(GATEWAY_URL, json={"validated": validated, "siem": {}}, timeout=10.0)
    dr.raise_for_status()
    return dr.json()

def main():
    cic_files = _list_csvs(CICIDS_DIR)
    if not cic_files:
        print(f"[sim] no CICIDS CSVs in {CICIDS_DIR}")
        sys.exit(0)

    wifi = _wifi()
    tls_rows = _tls()
    dev_rows = _devices() or [{}]

    # pool rows from all files (shuffle to avoid biased days)
    all_rows: List[Dict[str, Any]] = []
    for f in cic_files:
        try:
            rows = _read_csv(f)
            random.shuffle(rows)
            all_rows.extend(rows[:300])   # cap per file to keep it light
        except Exception:
            pass
    random.shuffle(all_rows)

    sent = 0
    with httpx.Client() as client:
        for row in all_rows:
            dev = random.choice(dev_rows)
            sig = _mk_signals(row, wifi, tls_rows, dev)
            if not sig.get("ip_geo") and not sig.get("tls_fp") and not sig.get("device_posture"):
                # too empty to be meaningful
                continue
            try:
                out = _post_validate_and_decide(client, sig)
                print(json.dumps({"ok": True, **out}))
            except Exception as e:
                print(json.dumps({"ok": False, "error": str(e)}))
            sent += 1
            time.sleep(SLEEP_BETWEEN)
            if sent >= MAX_ROWS:
                break
    print("[sim] done")

if __name__ == "__main__":
    main()