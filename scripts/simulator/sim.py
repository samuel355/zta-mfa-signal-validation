#!/usr/bin/env python3
# dataset-only, multi-file, randomized per-session
import os, sys, csv, json, random, time
from typing import Dict, Any, List
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

def _read_csv(path: str) -> List[Dict[str, Any]]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

def _list_csvs(dirpath: str) -> List[str]:
    return [os.path.join(dirpath, f) for f in os.listdir(dirpath) if f.endswith(".csv")]

def _wifi_rows() -> List[Dict[str, Any]]:
    try:
        rows = _read_csv(WIFI_CSV)
        # keep rows that have at least a bssid
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

def _mk_signals(row: Dict[str, Any],
                wifi_row: Dict[str, Any] | None,
                tls_row:  Dict[str, Any] | None,
                dev_row:  Dict[str, Any] | None) -> Dict[str, Any]:
    sig: Dict[str, Any] = {}

    # stable correlator
    sig["session_id"] = f"sess-{random.randrange(100000,999999)}"

    # label direct from CICIDS (often BENIGN)
    lab = row.get("Label") or row.get(" label") or row.get("LABEL")
    if lab is not None:
        sig["label"] = str(lab).strip()

    # IP (varies by CICIDS row)
    src_ip = row.get("Src IP") or row.get(" Source IP") or row.get("Src_IP") or row.get("src_ip")
    if src_ip:
        sig["ip_geo"] = {"ip": str(src_ip).strip()}

    # Wi-Fi BSSID + optional GPS from Wi-Fi CSV (random per session)
    if wifi_row:
        bssid = wifi_row.get("bssid") or wifi_row.get("BSSID")
        if bssid:
            sig["wifi_bssid"] = {"bssid": str(bssid).lower()}
        if USE_GPS_FROM_WIFI:
            lat = wifi_row.get("lat") or wifi_row.get("Lat") or wifi_row.get("latitude")
            lon = wifi_row.get("lon") or wifi_row.get("Lon") or wifi_row.get("longitude")
            try:
                if lat not in (None, "") and lon not in (None, ""):
                    sig["gps"] = {"lat": float(lat), "lon": float(lon)}
            except Exception:
                pass

    # Device posture (random per session)
    if dev_row:
        dev_id = dev_row.get("device_id") or dev_row.get("Device_ID") or dev_row.get("deviceId")
        if dev_id:
            sig["device_posture"] = {"device_id": str(dev_id)}

    # TLS JA3 (random per session)
    if tls_row:
        ja3 = tls_row.get("ja3") or tls_row.get("JA3")
        if ja3:
            sig["tls_fp"] = {"ja3": str(ja3)}

    return sig

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

def main():
    cic_files = _list_csvs(CICIDS_DIR)
    if not cic_files:
        print(f"[sim] no CICIDS CSVs in {CICIDS_DIR}")
        sys.exit(0)

    wifi_pool = _wifi_rows()
    tls_pool  = _tls_rows()
    dev_pool  = _device_rows() or [{}]

    # Collect from all CICIDS files (cap per file to keep CPU/IO reasonable)
    all_rows: List[Dict[str, Any]] = []
    for f in cic_files:
        try:
            rows = _read_csv(f)
            random.shuffle(rows)
            all_rows.extend(rows[:500])   # consider more variety
        except Exception:
            pass
    random.shuffle(all_rows)

    sent = 0
    with httpx.Client() as client:
        for row in all_rows:
            wifi_row = random.choice(wifi_pool) if wifi_pool else None
            tls_row  = random.choice(tls_pool)  if tls_pool  else None
            dev_row  = random.choice(dev_pool)  if dev_pool  else None

            sig = _mk_signals(row, wifi_row, tls_row, dev_row)
            if not any(k in sig for k in ("ip_geo","wifi_bssid","tls_fp","device_posture")):
                # skip rows that contribute nothing
                continue

            try:
              out = _post_validate_and_decide(client, sig)
              print(json.dumps(out))
              # jittered pacing so we don't burst
              time.sleep(SLEEP_BETWEEN * random.uniform(0.8, 1.3))
            except Exception as e:
                print(json.dumps({"ok": False, "error": str(e)}))

            sent += 1
            time.sleep(SLEEP_BETWEEN)
            if sent >= MAX_ROWS:
                break

    print("[sim] done")

if __name__ == "__main__":
    main()