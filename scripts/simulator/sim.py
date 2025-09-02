#!/usr/bin/env python3
import os, sys, time, json, csv, random, datetime as dt
import httpx

# ----------- CONFIG (env overrides) -----------
DATA_DIR      = os.getenv("DATA_DIR", "/work/data")
CICIDS_DIR    = os.getenv("CICIDS_DIR", f"{DATA_DIR}/cicids")
WIFI_CSV      = os.getenv("WIFI_CSV",  f"{DATA_DIR}/wifi/wigle_sample.csv")
DEVICE_CSV    = os.getenv("DEVICE_CSV",f"{DATA_DIR}/device_posture/device_posture.csv")
TLS_CSV       = os.getenv("TLS_CSV",   f"{DATA_DIR}/tls/ja3_fingerprints.csv")

VALIDATE_URL  = os.getenv("VALIDATE_URL", "http://validation:8000/validate")
GATEWAY_URL   = os.getenv("GATEWAY_URL",  "http://gateway:8000/decision")

SLEEP_BETWEEN = float(os.getenv("SIM_SLEEP", "0.8"))
MAX_ROWS      = int(os.getenv("SIM_MAX_ROWS", "150"))

# ----------- helpers to load datasets -----------
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

def load_all_rows(path):
    try:
        with open(path, newline="") as f:
            return list(csv.DictReader(f))
    except Exception:
        return []

# Wi-Fi reference (used for known BSSID + base GPS)
WIFI_HEADERS = ["bssid","ssid","lat","lon"]
wifi_row     = load_first_row_or_default(WIFI_CSV, WIFI_HEADERS)
KNOWN_BSSID  = wifi_row.get("bssid","aa:bb:cc:dd:ee:ff").lower()
BASE_LAT     = float(wifi_row.get("lat", "5.6037") or 5.6037)
BASE_LON     = float(wifi_row.get("lon", "-0.1870") or -0.1870)

# TLS fingerprints (pick one per session; tag drives TLS_ANOMALY or benign)
tls_rows     = load_all_rows(TLS_CSV)  # fields: ja3,tag
def pick_tls():
    if not tls_rows:
        return {"ja3": "771,4865-4867-4866,23-65281,29-23,0", "tag": "ok"}
    row = random.choice(tls_rows)
    return {"ja3": row.get("ja3",""), "tag": (row.get("tag") or "").lower()}

# Device posture (one device_id, with posture fields for POSTURE_OUTDATED)
device_row   = load_first_row_or_default(DEVICE_CSV, ["device_id","os","patched","edr","last_update"])
DEVICE_ID    = device_row.get("device_id","dev-001")
DEVICE_PATCHED = str(device_row.get("patched","true")).lower() == "true"

# CICIDS file discovery
def cicids_files():
    if not os.path.isdir(CICIDS_DIR):
        return []
    files = []
    for fn in sorted(os.listdir(CICIDS_DIR)):
        if fn.endswith(".csv"):
            files.append(os.path.join(CICIDS_DIR, fn))
    return files

def row_iter(path):
    with open(path, newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            yield row

# ----------- reason derivation from CICIDS label + datasets -----------
def reasons_from_label(label: str) -> list[str]:
    """Map CICIDS label → high-level reasons used by Trust/SIEM."""
    L = (label or "BENIGN").strip().upper()

    # Common CICIDS labels include:
    #  BENIGN, DoS Hulk/GoldenEye/Slowloris/Slowhttptest, DDoS,
    #  PortScan, Bot, Infiltration, Web Attack Brute Force/XSS/Sqli,
    #  FTP-Patator, SSH-Patator, Heartbleed
    reasons = []
    if L == "BENIGN":
        return reasons

    # DoS / DDoS / Scans → brute force / DoS behavior
    if "DDOS" in L or L.startswith("DOS") or "PORTSCAN" in L:
        reasons.append("BRUTE_FORCE")

    # Credential attacks
    if "PATATOR" in L or "BRUTE FORCE" in L:
        reasons.append("CREDENTIAL_STUFFING")

    # App-layer web attacks
    if "WEB ATTACK" in L or "SQLI" in L or "XSS" in L:
        reasons.append("POLICY_ELEVATION")

    # Bot infections / Infiltration → exfil / malware
    if "BOT" in L or "INFILTRATION" in L:
        reasons.append("DOWNLOAD_EXFIL")

    # Heartbleed → TLS anomaly
    if "HEARTBLEED" in L:
        reasons.append("TLS_ANOMALY")

    return list(dict.fromkeys(reasons))  # uniq, preserve order

def reason_from_tls_tag(tag: str) -> list[str]:
    t = (tag or "").lower()
    if not t:
        return []
    # assume tls CSV tags like "ok/benign" vs "suspicious/malware/anon"
    if t in ("ok","benign","known_good","browser"):
        return []
    return ["TLS_ANOMALY"]

def reason_from_device_posture(patched: bool) -> list[str]:
    return [] if patched else ["POSTURE_OUTDATED"]

def build_signals_and_reasons_from_cicids(row):
    """Use CICIDS + datasets to craft signals + reasons."""
    src_ip = row.get("Src IP") or row.get(" Source IP") or row.get("Src_IP") or "203.0.113.10"
    label  = (row.get("Label") or "BENIGN").strip()

    # Start with dataset-driven reasons
    reasons = reasons_from_label(label)

    # Base GPS near known Wi-Fi location
    gps_lat, gps_lon = BASE_LAT, BASE_LON

    # For movement-related categories, perturb GPS to create GPS_MISMATCH
    if any(k in label.upper() for k in ["DDOS", "DOS", "PORTSCAN", "INFILTRATION", "BOT"]):
        # ~133km offset to exceed our 50km mismatch heuristic
        gps_lat = round(gps_lat + 1.2, 6)
        gps_lon = round(gps_lon + 1.2, 6)
        reasons.append("GPS_MISMATCH")

    # Wi-Fi: use known BSSID normally; for scanning/DoS, use unknown to cause WIFI_MISMATCH
    bssid = KNOWN_BSSID
    if any(k in label.upper() for k in ["DDOS", "DOS", "PORTSCAN"]):
        bssid = "de:ad:be:ef:00:%02x" % random.randint(2, 254)  # not in wigle_sample.csv
        reasons.append("WIFI_MISMATCH")

    # TLS: pick a TLS JA3 + derive TLS_ANOMALY from its tag if suspicious
    tls_pick = pick_tls()
    tls_ja3, tls_tag = tls_pick.get("ja3",""), tls_pick.get("tag","")
    reasons += reason_from_tls_tag(tls_tag)

    # Device posture: mark outdated if dataset says patched == false
    reasons += reason_from_device_posture(DEVICE_PATCHED)

    # Stable session per row
    sess = f"sess-{random.randrange(100000,999999)}"

    signals = {
        "ip_geo": {"ip": src_ip},
        "gps": {"lat": gps_lat, "lon": gps_lon, "age_s": random.randint(1, 30)},
        "wifi_bssid": {"bssid": bssid},
        "device_posture": {"device_id": DEVICE_ID},
        "tls_fp": {"ja3": tls_ja3},
        "session_id": sess,
        "label": label
    }

    # Uniq + clean reasons
    reasons = [r for r in dict.fromkeys(reasons) if r]
    return signals, reasons

# ----------- downstream integration -----------
def post_validate_and_decide(client, signals, reasons):
    # 1) validate
    vreq = {"signals": signals}
    vr = client.post(VALIDATE_URL, json=vreq, timeout=10.0)
    vr.raise_for_status()
    vout = vr.json()
    validated = vout.get("validated", {}) or {}

    # Merge validation reasons (if any) with dataset-derived reasons
    v_reasons = vout.get("reasons")
    if isinstance(v_reasons, list):
        reasons = [str(x) for x in v_reasons if x] + [r for r in reasons if r]

    # Thread reasons into vector for Trust
    if isinstance(validated, dict):
        vec = validated.get("vector") or {}
        vec["reasons"] = [str(x) for x in reasons if x]
        validated["vector"] = vec

    # 2) decision
    dreq = {"validated": validated, "siem": {}}
    dr = client.post(GATEWAY_URL, json=dreq, timeout=10.0)
    dr.raise_for_status()
    dout = dr.json()

    return {
        "session_id": dout.get("session_id", validated.get("vector",{}).get("session_id")),
        "decision":   dout.get("enforcement"),
        "risk":       round(float(dout.get("risk", 0.0)), 4),
        "label":      validated.get("vector",{}).get("label","BENIGN")
    }

# ----------- main -----------
def main():
    files = cicids_files()
    if not files:
        print(f"[sim] no CICIDS CSVs in {CICIDS_DIR}; nothing to replay")
        sys.exit(0)

    sent = 0
    with httpx.Client() as client:
        for path in files:
            for row in row_iter(path):
                signals, reasons = build_signals_and_reasons_from_cicids(row)
                try:
                    out = post_validate_and_decide(client, signals, reasons)
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