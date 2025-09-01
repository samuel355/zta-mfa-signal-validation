#!/usr/bin/env python3
import os, sys, time, json, csv, random, datetime as dt
import httpx

# ----------- CONFIG (env overrides) -----------
DATA_DIR      = os.getenv("DATA_DIR", "/work/data")    # mount host ./data to /work/data
CICIDS_DIR    = os.getenv("CICIDS_DIR", f"{DATA_DIR}/cicids")
WIFI_CSV      = os.getenv("WIFI_CSV",  f"{DATA_DIR}/wifi/wigle_sample.csv")
DEVICE_CSV    = os.getenv("DEVICE_CSV",f"{DATA_DIR}/device_posture/device_posture.csv")
TLS_CSV       = os.getenv("TLS_CSV",   f"{DATA_DIR}/tls/ja3_fingerprints.csv")

VALIDATE_URL  = os.getenv("VALIDATE_URL", "http://validation:8000/validate")
GATEWAY_URL   = os.getenv("GATEWAY_URL",  "http://gateway:8000/decision")

SLEEP_BETWEEN = float(os.getenv("SIM_SLEEP", "0.8"))   # seconds between sessions
MAX_ROWS      = int(os.getenv("SIM_MAX_ROWS", "150"))  # stop early for demo

# ----------- load helper lookups -----------
def load_first_row_or_default(path, headers):
    try:
        with open(path, newline="") as f:
            r = csv.DictReader(f)
            row = next(r, None)
            if row: return row
    except Exception:
        pass
    return {h: "" for h in headers}

def load_random_row(path):
    try:
        with open(path, newline="") as f:
            r = list(csv.DictReader(f))
            if r: return random.choice(r)
    except Exception:
        pass
    return {}

WIFI_HEADERS = ["bssid","ssid","lat","lon"]
wifi_row   = load_first_row_or_default(WIFI_CSV, WIFI_HEADERS)
tls_row    = load_random_row(TLS_CSV)       # fields: ja3,tag
device_row = load_first_row_or_default(DEVICE_CSV, ["device_id","os","patched","edr","last_update"])

WIFI_BSSID = wifi_row.get("bssid","aa:bb:cc:dd:ee:ff")
TLS_JA3    = tls_row.get("ja3","771,4865-4867-4866,23-65281,29-23,0")
DEVICE_ID  = device_row.get("device_id","dev-001")

# ----------- pick CICIDS files present -----------
def cicids_files():
    if not os.path.isdir(CICIDS_DIR):
        return []
    files = []
    for fn in sorted(os.listdir(CICIDS_DIR)):
        if fn.endswith(".csv"):
            files.append(os.path.join(CICIDS_DIR, fn))
    return files

def row_iter(path):
    # CICIDS CSV uses commas; has columns like: Src IP, Dst IP, Flow Duration, Label, ...
    with open(path, newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            yield row

def mk_signals_from_cicids(row):
    """
    Minimal mapping to our signals:
      - ip_geo.ip from Src IP
      - gps is synthetic (same each run; enrichment will be used mainly for ip)
      - wifi_bssid from sample CSV
      - device_posture uses device_id (enriched by Validation)
      - tls_fp.ja3 from TLS sample CSV
    """
    src_ip = row.get("Src IP") or row.get(" Source IP") or row.get("Src_IP") or "203.0.113.10"
    label  = row.get("Label","BENIGN")
    # attach session_id so downstream SIEM aggregation lines up
    sess = f"sess-{random.randrange(100000,999999)}"
    gps = {"lat": float(wifi_row.get("lat", "5.6037") or 5.6037),
           "lon": float(wifi_row.get("lon", "-0.1870") or -0.1870),
           "age_s": random.randint(1, 30)}
    vec = {
        "ip_geo": {"ip": src_ip},
        "gps": gps,
        "wifi_bssid": {"bssid": WIFI_BSSID},
        "device_posture": {"device_id": DEVICE_ID},
        "tls_fp": {"ja3": TLS_JA3},
        "session_id": sess,
        "label": label
    }
    return vec

def post_validate_and_decide(client, signals):
    # 1) validate
    vreq = {"signals": signals}
    vr = client.post(VALIDATE_URL, json=vreq, timeout=10.0)
    vr.raise_for_status()
    vout = vr.json()
    validated = vout.get("validated", {})
    # 2) decision
    dreq = {"validated": validated, "siem": {}}
    dr = client.post(GATEWAY_URL, json=dreq, timeout=10.0)
    dr.raise_for_status()
    dout = dr.json()
    # brief console line
    return {
        "session_id": dout.get("session_id", validated.get("vector",{}).get("session_id")),
        "decision":   dout.get("enforcement"),
        "risk":       round(float(dout.get("risk", 0.0)), 4),
        "label":      validated.get("vector",{}).get("label","BENIGN")
    }

def main():
    files = cicids_files()
    if not files:
        print(f"[sim] no CICIDS CSVs in {CICIDS_DIR}; nothing to replay")
        sys.exit(0)

    sent = 0
    with httpx.Client() as client:
        for path in files:
            for row in row_iter(path):
                sig = mk_signals_from_cicids(row)
                try:
                    out = post_validate_and_decide(client, sig)
                    print(json.dumps({"ok": True, **out}))
                except Exception as e:
                    print(json.dumps({"ok": False, "error": str(e)}))
                sent += 1
                time.sleep(SLEEP_BETWEEN)
                if sent >= MAX_ROWS:
                    print(f"[sim] reached SIM_MAX_ROWS={MAX_ROWS}, stopping")
                    return
    print("[sim] done")

if __name__ == "__main__":
    main()