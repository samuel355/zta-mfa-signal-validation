#!/usr/bin/env python3
"""
Standalone CICIDS ingest preview (dataset-only, no defaults).
- Scans ALL CICIDS CSVs
- Samples rows (attack-biased) but never fabricates values
- Prints signals as they exist in the datasets; if a value is missing, the field is omitted.
"""

import os, csv, json, random, pathlib
from typing import Dict, Any, List, Tuple
from collections import Counter

# ---------- Paths (override via env) ----------
DATA_DIR   = os.getenv("DATA_DIR", "/app/data")
CICIDS_DIR = os.getenv("CICIDS_DIR", f"{DATA_DIR}/cicids")
WIFI_CSV   = os.getenv("WIFI_CSV",  f"{DATA_DIR}/wifi/wigle_sample.csv")
TLS_CSV    = os.getenv("TLS_CSV",   f"{DATA_DIR}/tls/ja3_fingerprints.csv")
DEVICE_CSV = os.getenv("DEVICE_CSV",f"{DATA_DIR}/device_posture/device_posture.csv")

# ---------- Sampling knobs ----------
PRINT_MAX = int(os.getenv("PREVIEW_PRINT_MAX", "30"))
MAX_SCAN_ROWS_PER_FILE = int(os.getenv("PREVIEW_MAX_SCAN_PER_FILE", "120"))
MAX_ATTACK_POOL = int(os.getenv("PREVIEW_MAX_ATTACK_POOL", "4000"))
MAX_BENIGN_POOL = int(os.getenv("PREVIEW_MAX_BENIGN_POOL", "4000"))
ATTACK_FRACTION = float(os.getenv("PREVIEW_ATTACK_FRACTION", "0.80"))

# ---------- Utils ----------
def _exists(path: str, kind: str):
    p = pathlib.Path(path)
    if not p.exists():
        raise SystemExit(f"[ERR] {kind} missing at {path}")
    print(f"[ok] {kind}: {path}")

def _read_csv(path: str, limit: int | None = None) -> List[Dict[str, Any]]:
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    if limit is not None:
        random.shuffle(rows)
        rows = rows[:limit]
    return rows

def _list_cicids_files(dir_path: str) -> List[str]:
    p = pathlib.Path(dir_path)
    files = [str(q) for q in p.glob("*.csv")]
    random.shuffle(files)
    return files

# ---------- Load side datasets exactly as-is ----------
def _wifi_row(path: str) -> Dict[str, Any]:
    try:
        rows = _read_csv(path, 1)
        return rows[0] if rows else {}
    except Exception:
        return {}

def _tls_rows(path: str) -> List[Dict[str, str]]:
    try:
        return _read_csv(path)
    except Exception:
        return []

def _device_row(path: str) -> Dict[str, Any]:
    try:
        rows = _read_csv(path, 1)
        return rows[0] if rows else {}
    except Exception:
        return {}

# ---------- Reasons (dataset-only) ----------
def _reasons_from_label(label: str | None) -> List[str]:
    if not label:
        return []
    L = str(label).strip().upper()
    if L == "BENIGN":
        return []
    rs: List[str] = []
    if "DDOS" in L or L.startswith("DOS") or "PORTSCAN" in L: rs.append("BRUTE_FORCE")
    if "PATATOR" in L or "BRUTE FORCE" in L: rs.append("CREDENTIAL_STUFFING")
    if "WEB ATTACK" in L or "SQLI" in L or "XSS" in L: rs.append("POLICY_ELEVATION")
    if "BOT" in L or "INFILTRATION" in L: rs.append("DOWNLOAD_EXFIL")
    if "HEARTBLEED" in L: rs.append("TLS_ANOMALY")
    return list(dict.fromkeys(rs))

def _reasons_from_tls_tag(tag: str | None) -> List[str]:
    if not tag:
        return []
    t = str(tag).strip().lower()
    if t in ("ok", "benign", "known_good", "browser", ""):
        return []
    return ["TLS_ANOMALY"]

def _reasons_from_device_patched(patched: str | bool | None) -> List[str]:
    if patched is None:
        return []
    if isinstance(patched, str):
        patched = patched.strip().lower() == "true"
    return [] if patched else ["POSTURE_OUTDATED"]

# ---------- Attack check (accepts None safely) ----------
def _is_attack(label: Any) -> bool:
    if label is None:
        return False
    return str(label).strip().upper() != "BENIGN"

# ---------- Build signals strictly from datasets ----------
def build_signals_and_reasons(
    row: Dict[str, Any],
    wifi: Dict[str, Any],
    tls_all: List[Dict[str, str]],
    device: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[str]]:

    label = row.get("Label")
    reasons = _reasons_from_label(label)

    signals: Dict[str, Any] = {}
    sess = f"sess-{random.randrange(100000, 999999)}"

    # ip_geo from CICIDS (Src IP variants)
    src_ip = row.get("Src IP") or row.get(" Source IP") or row.get("Src_IP")
    if src_ip:
        signals["ip_geo"] = {"ip": src_ip}

    # gps from wifi ref row if lat/lon exist in that CSV (no fabrication)
    try:
        lat = wifi.get("lat") or wifi.get("Lat") or wifi.get("latitude")
        lon = wifi.get("lon") or wifi.get("Lon") or wifi.get("longitude")
        if lat is not None and lon is not None and str(lat) != "" and str(lon) != "":
            signals["gps"] = {"lat": float(lat), "lon": float(lon)}
    except Exception:
        pass

    # wifi_bssid directly from wifi CSV if present (no synthetic)
    bssid = wifi.get("bssid") or wifi.get("BSSID")
    if bssid:
        signals["wifi_bssid"] = {"bssid": str(bssid).lower()}

    # tls_fp: pick a random JA3 row if TLS CSV has any; do not invent
    if tls_all:
        pick = random.choice(tls_all)
        ja3 = pick.get("ja3") or pick.get("JA3")
        if ja3:
            signals["tls_fp"] = {"ja3": ja3}
            reasons += _reasons_from_tls_tag(pick.get("tag") or pick.get("Tag"))

    # device posture strictly from device CSV
    dev_id = device.get("device_id") or device.get("Device_ID") or device.get("deviceId")
    if dev_id:
        signals["device_posture"] = {"device_id": dev_id}
        reasons += _reasons_from_device_patched(device.get("patched") or device.get("Patched"))

    # always carry through label & a session id (session id is generated here for correlation)
    if label is not None:
        signals["label"] = label
    signals["session_id"] = sess

    # unique reasons, keep order
    reasons = [r for r in dict.fromkeys(reasons) if r]
    return signals, reasons

# ---------- Main ----------
def main():
    print("=== CICIDS Ingest Preview (dataset-only, all files) ===")
    _exists(DATA_DIR,   "DATA_DIR")
    _exists(CICIDS_DIR, "CICIDS_DIR")
    _exists(WIFI_CSV,   "WIFI_CSV")
    _exists(TLS_CSV,    "TLS_CSV")
    _exists(DEVICE_CSV, "DEVICE_CSV")

    wifi    = _wifi_row(WIFI_CSV)
    tls_all = _tls_rows(TLS_CSV)
    device  = _device_row(DEVICE_CSV)

    files = _list_cicids_files(CICIDS_DIR)
    if not files:
        raise SystemExit("[ERR] No CICIDS CSV files found")
    print(f"[info] scanning {len(files)} CICIDS files (<= {MAX_SCAN_ROWS_PER_FILE} rows per file)")

    attack_pool: List[Dict[str, Any]] = []
    benign_pool: List[Dict[str, Any]] = []

    for path in files:
        rows = _read_csv(path, MAX_SCAN_ROWS_PER_FILE)
        for row in rows:
            if _is_attack(row.get("Label")):
                if len(attack_pool) < MAX_ATTACK_POOL:
                    attack_pool.append(row)
            else:
                if len(benign_pool) < MAX_BENIGN_POOL:
                    benign_pool.append(row)

    print(f"[info] pooled rows: attack={len(attack_pool)} benign={len(benign_pool)}")
    if not attack_pool and not benign_pool:
        raise SystemExit("[ERR] No rows collected from CICIDS")

    # sample mix
    n_attack = min(int(PRINT_MAX * ATTACK_FRACTION), len(attack_pool))
    n_benign = min(PRINT_MAX - n_attack, len(benign_pool))
    if n_attack + n_benign < PRINT_MAX:  # backfill if needed
        if len(attack_pool) > n_attack:
            n_attack = min(PRINT_MAX - n_benign, len(attack_pool))
        elif len(benign_pool) > n_benign:
            n_benign = min(PRINT_MAX - n_attack, len(benign_pool))

    random.shuffle(attack_pool)
    random.shuffle(benign_pool)
    sample_rows = attack_pool[:n_attack] + benign_pool[:n_benign]
    random.shuffle(sample_rows)

    labels = Counter()
    reasons_hist = Counter()

    for row in sample_rows:
        signals, reasons = build_signals_and_reasons(row, wifi, tls_all, device)
        label = row.get("Label")
        labels[str(label).strip().upper() if label is not None else "NONE"] += 1
        for r in reasons:
            reasons_hist[r] += 1
        print(json.dumps({"label": label, "signals": signals, "reasons": reasons}, indent=2))

    print("\n--- Summary ---")
    print("labels :", dict(labels))
    print("reasons:", dict(reasons_hist))
    print(f"hint   : set PREVIEW_ATTACK_FRACTION (now {ATTACK_FRACTION}) and PRINT_MAX (now {PRINT_MAX}).")

if __name__ == "__main__":
    main()