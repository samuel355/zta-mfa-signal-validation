#!/usr/bin/env python3
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

SLEEP_BETWEEN = float(os.getenv("SIM_SLEEP", "0.6"))
MAX_ROWS      = int(os.getenv("SIM_MAX_ROWS", "200"))
MAX_PER_FILE  = int(os.getenv("SIM_MAX_PER_FILE", "600"))
BENIGN_KEEP   = float(os.getenv("SIM_BENIGN_KEEP", "0.10"))
USE_GPS_FROM_WIFI = os.getenv("SIM_USE_GPS_FROM_WIFI","true").lower() in {"1","true","yes","on"}
MODE = os.getenv("SIM_MODE","stride_balanced").lower()

# floors to avoid 'missing'
MIN_WIFI   = float(os.getenv("SIM_MIN_WIFI", "0.9"))
MIN_GPS    = float(os.getenv("SIM_MIN_GPS", "0.85"))
MIN_TLS    = float(os.getenv("SIM_MIN_TLS", "0.7"))
MIN_DEVICE = float(os.getenv("SIM_MIN_DEVICE", "0.85"))
GPS_OFFSET_KM = float(os.getenv("SIM_GPS_OFFSET_KM","600"))

# class mix for STRIDE-balanced
P_SPOOF   = float(os.getenv("SIM_PCT_SPOOFING","0.20"))
P_TLS     = float(os.getenv("SIM_PCT_TLS_TAMPERING","0.15"))
P_DOS     = float(os.getenv("SIM_PCT_DOS","0.20"))
P_EXFIL   = float(os.getenv("SIM_PCT_EXFIL","0.15"))
P_EOP     = float(os.getenv("SIM_PCT_EOP","0.15"))
P_REP     = float(os.getenv("SIM_PCT_REPUDIATION","0.15"))

def _read_csv(p): 
    with open(p, newline="") as f: 
        return list(csv.DictReader(f))

def _list_csvs(dirpath): 
    return [os.path.join(dirpath, f) for f in os.listdir(dirpath) if f.endswith(".csv")]

def _wifi_pool():
    try: 
        rows = _read_csv(WIFI_CSV)
        return [r for r in rows if (r.get("bssid") or r.get("BSSID"))]
    except Exception: 
        return []

def _dev_pool():
    try: 
        return _read_csv(DEVICE_CSV)
    except Exception: 
        return []

def _tls_pool():
    try: 
        return _read_csv(TLS_CSV)
    except Exception: 
        return []

def _to_float(x)->Optional[float]:
    try: return float(str(x).strip())
    except: return None

def _offset_gps(lat, lon, km):
    from math import radians, cos
    dlat = km/111.0
    dlon = (km/(111.0*max(0.15,cos(radians(lat))))) * (1 if random.random()<0.5 else -1)
    return lat + (dlat if random.random()<0.5 else -dlat), lon + dlon

def _pick_tls_row(pool, bad_only=False):
    if not pool: return None
    badtags = {"tor_suspect","malware_family_x","scanner_tool","cloud_proxy","old_openssl","insecure_client","honeypot_fingerprint"}
    if bad_only:
        bad = [r for r in pool if (r.get("tag") or r.get("Tag") or "").strip().lower() in badtags]
        return random.choice(bad) if bad else None
    # weighted benign
    weights=[]
    for r in pool:
        tag=(r.get("tag") or r.get("Tag") or "").strip().lower()
        weights.append(0.2 if tag in badtags else 1.0)
    try:
        return random.choices(pool, weights=weights, k=1)[0]
    except:
        return random.choice(pool)

def _ensure_floors(sig, row, wifi_pool, tls_pool, dev_pool):
    # ip_geo from CICIDS
    if "ip_geo" not in sig:
        for k in ("Src IP"," Source IP","Src_IP","src_ip"):
            v=row.get(k)
            if v: sig["ip_geo"]={"ip":str(v).strip()}; break
    # wifi + gps
    if "wifi_bssid" not in sig and wifi_pool and random.random()<MIN_WIFI:
        w=random.choice(wifi_pool); b=w.get("bssid") or w.get("BSSID")
        if b: 
            sig["wifi_bssid"]={"bssid":str(b).lower()}
            if USE_GPS_FROM_WIFI and "gps" not in sig:
                lat=_to_float(w.get("lat") or w.get("Lat") or w.get("latitude"))
                lon=_to_float(w.get("lon") or w.get("Lon") or w.get("longitude"))
                if lat is not None and lon is not None:
                    sig["gps"]={"lat":lat,"lon":lon}
    if "gps" not in sig and "wifi_bssid" in sig and wifi_pool and random.random()<MIN_GPS:
        bssid=sig["wifi_bssid"]["bssid"]
        w=next((x for x in wifi_pool if str(x.get("bssid") or x.get("BSSID")).lower()==bssid), None)
        if w:
            lat=_to_float(w.get("lat") or w.get("Lat") or w.get("latitude"))
            lon=_to_float(w.get("lon") or w.get("Lon") or w.get("longitude"))
            if lat is not None and lon is not None:
                sig["gps"]={"lat":lat,"lon":lon}
    # tls
    if "tls_fp" not in sig and tls_pool and random.random()<MIN_TLS:
        r=_pick_tls_row(tls_pool, bad_only=False)
        if r and (r.get("ja3") or r.get("JA3")):
            sig["tls_fp"]={"ja3":str(r.get("ja3") or r.get("JA3"))}
    # device
    if "device_posture" not in sig and dev_pool and random.random()<MIN_DEVICE:
        d=random.choice(dev_pool); dev_id=d.get("device_id") or d.get("Device_ID") or d.get("deviceId")
        if dev_id:
            patched=str(d.get("patched","true")).strip().lower()=="true"
            sig["device_posture"]={"device_id":str(dev_id),"patched":patched}

def _make_spoofing(sig: Dict[str, Any], wifi_pool: List[Dict[str, Any]]) -> None:
    """
    Inject GPS spoofing relative to Wi-Fi (even if GPS already exists).
    Creates non-zero ip_wifi_distance_km so Validation yields SPOOFING reasons.
    """
    if "wifi_bssid" not in sig or not wifi_pool:
        return

    # bssid we already placed in the signal
    bssid = str(sig.get("wifi_bssid", {}).get("bssid") or "").lower()
    if not bssid:
        return

    # find a Wi-Fi row for that BSSID
    w = next(
        (x for x in wifi_pool
         if str(x.get("bssid") or x.get("BSSID") or "").lower() == bssid),
        None
    )
    if not w:
        return

    lat = _to_float(w.get("lat") or w.get("Lat") or w.get("latitude"))
    lon = _to_float(w.get("lon") or w.get("Lon") or w.get("longitude"))
    if lat is None or lon is None:
        return

    g_lat, g_lon = _offset_gps(lat, lon, GPS_OFFSET_KM)
    sig["gps"] = {"lat": g_lat, "lon": g_lon}


def _mk_signals(
    row: Dict[str, Any],
    wifi_row: Optional[Dict[str, Any]],
    tls_row: Optional[Dict[str, Any]],
    dev_row: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a single session's raw signals, with strict casting/guards."""
    sig: Dict[str, Any] = {}
    sig["session_id"] = f"sess-{random.randrange(100000, 999999)}"

    # label from CICIDS
    lab = row.get("Label") or row.get(" label") or row.get("LABEL")
    if lab is not None:
        sig["label"] = str(lab).strip()

    # Source IP (several header variants in CICIDS)
    src_ip = (
        row.get("Src IP")
        or row.get(" Source IP")
        or row.get("Src_IP")
        or row.get("src_ip")
        or None
    )
    if src_ip is not None and str(src_ip).strip():
        sig["ip_geo"] = {"ip": str(src_ip).strip()}

    # Wi-Fi (BSSID + optional GPS)
    if wifi_row:
        b = wifi_row.get("bssid") or wifi_row.get("BSSID") or ""
        bssid = str(b).strip().lower()
        if bssid:
            sig["wifi_bssid"] = {"bssid": bssid}

        if USE_GPS_FROM_WIFI:
            lat = _to_float(wifi_row.get("lat") or wifi_row.get("Lat") or wifi_row.get("latitude"))
            lon = _to_float(wifi_row.get("lon") or wifi_row.get("Lon") or wifi_row.get("longitude"))
            if lat is not None and lon is not None:
                sig["gps"] = {"lat": lat, "lon": lon}

    # Device posture
    if dev_row:
        dev_id = dev_row.get("device_id") or dev_row.get("Device_ID") or dev_row.get("deviceId")
        if dev_id is not None and str(dev_id).strip():
            patched_raw = str(dev_row.get("patched", "true")).strip().lower()
            patched = True if patched_raw not in {"true", "false"} else (patched_raw == "true")
            sig["device_posture"] = {"device_id": str(dev_id), "patched": patched}

    # TLS JA3
    if tls_row:
        ja3 = tls_row.get("ja3") or tls_row.get("JA3")
        if ja3 is not None and str(ja3).strip():
            sig["tls_fp"] = {"ja3": str(ja3).strip()}

    return sig


def _post_validate_and_decide(client, signals):
    try:
        vr = client.post(VALIDATE_URL, json={"signals": signals}, timeout=10)
        vr.raise_for_status()
        validated=vr.json().get("validated",{})
    except Exception as e:
        return {"ok": False, "stage": "validate", "error": str(e)}
    try:
        dr = client.post(GATEWAY_URL, json={"validated": validated, "siem": {}}, timeout=10)
        dr.raise_for_status()
        return {"ok": True, **dr.json()}
    except Exception as e:
        return {"ok": False, "stage": "decision", "error": str(e)}

def main():
    cic_files=_list_csvs(CICIDS_DIR)
    if not cic_files:
        print(f"[sim] no CICIDS in {CICIDS_DIR}"); sys.exit(0)
    wifi_pool=_wifi_pool(); tls_pool=_tls_pool(); dev_pool=_dev_pool() or [{}]
    print(f"[sim] pools: wifi={len(wifi_pool)} tls={len(tls_pool)} device={len(dev_pool)}")

    # build sample from CICIDS
    rows=[]
    for f in cic_files:
        try:
            r=_read_csv(f); random.shuffle(r)
            attacks, benign = [], []
            for x in r:
                lab=(x.get("Label") or x.get(" label") or "").strip().upper()
                if lab=="BENIGN":
                    if random.random()<BENIGN_KEEP: benign.append(x)
                else:
                    attacks.append(x)
            sample = (attacks+benign)[:MAX_PER_FILE]
            rows.extend(sample)
        except: pass
    random.shuffle(rows)

    # deterministic bucket chooser for STRIDE-balanced mode
    buckets=[("spoof",P_SPOOF),("tls",P_TLS),("dos",P_DOS),("exfil",P_EXFIL),("eop",P_EOP),("rep",P_REP)]
    total=sum(p for _,p in buckets) or 1.0
    cum=[]
    acc=0.0
    for k,p in buckets:
        acc+=p/total; cum.append((acc,k))

    sent=0
    with httpx.Client() as client:
        for row in rows:
            wifi_row = random.choice(wifi_pool) if wifi_pool else None
            tls_row  = _pick_tls_row(tls_pool, bad_only=False) if tls_pool else None
            dev_row  = random.choice(dev_pool) if dev_pool else None
            sig=_mk_signals(row, wifi_row, tls_row, dev_row)

            # force class
            r=random.random()
            bucket="spoof"
            for edge,k in cum:
                if r<=edge: bucket=k; break

            if bucket=="spoof":     _make_spoofing(sig, wifi_pool)
            elif bucket=="tls":     sig["tls_fp"]={"ja3": (_pick_tls_row(tls_pool, bad_only=True) or tls_row or {}).get("ja3","")} if tls_pool else sig
            elif bucket=="dos":     sig["label"]="DDOS"
            elif bucket=="exfil":   sig["label"]="INFILTRATION"
            elif bucket=="eop":     sig["label"]="WEB ATTACK"
            elif bucket=="rep":     sig["repudiation"]=True

            _ensure_floors(sig, row, wifi_pool, tls_pool, dev_pool)

            if not any(k in sig for k in ("ip_geo","wifi_bssid","tls_fp","device_posture","gps")):
                continue

            out=_post_validate_and_decide(client, sig)
            print(json.dumps(out))
            time.sleep(SLEEP_BETWEEN)
            sent+=1
            if sent>=MAX_ROWS: break
    print("[sim] done")

if __name__=="__main__":
    main()