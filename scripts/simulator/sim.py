#!/usr/bin/env python3
import os, sys, csv, json, random, time
from typing import Dict, Any, List, Optional
import httpx

# ------------------- Paths -------------------
DATA_DIR      = os.getenv("DATA_DIR", "/app/data")
CICIDS_DIR    = os.getenv("CICIDS_DIR", f"{DATA_DIR}/cicids")
WIFI_CSV      = os.getenv("WIFI_CSV",  f"{DATA_DIR}/wifi/wigle_sample.csv")
DEVICE_CSV    = os.getenv("DEVICE_CSV",f"{DATA_DIR}/device_posture/device_posture.csv")
TLS_CSV       = os.getenv("TLS_CSV",   f"{DATA_DIR}/tls/ja3_fingerprints.csv")

VALIDATE_URL  = os.getenv("VALIDATE_URL", "http://validation:8000/validate")
GATEWAY_URL   = os.getenv("GATEWAY_URL",  "http://gateway:8000/decision")

# ------------------- Knobs -------------------
SLEEP_BETWEEN = float(os.getenv("SIM_SLEEP", "0.6"))
MAX_ROWS      = int(os.getenv("SIM_MAX_ROWS", "200"))
MAX_PER_FILE  = int(os.getenv("SIM_MAX_PER_FILE", "600"))
BENIGN_KEEP   = float(os.getenv("SIM_BENIGN_KEEP", "0.10"))
USE_GPS_FROM_WIFI = os.getenv("SIM_USE_GPS_FROM_WIFI","true").lower() in {"1","true","yes","on"}

# floors to avoid “missing”
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

# ------------------- Helpers -------------------
def _get_src_ip(row: Dict[str, Any]) -> Optional[str]:
    for k, v in row.items():
        kk = str(k).replace("_"," ").strip().lower()
        if "src" in kk and "ip" in kk:
            s = str(v).strip()
            if s:
                return s
    return None

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
    badtags = {"tor_suspect","malware_family_x","scanner_tool",
               "cloud_proxy","old_openssl","insecure_client","honeypot_fingerprint"}
    if bad_only:
        bad = [r for r in pool if (r.get("tag") or r.get("Tag") or "").strip().lower() in badtags]
        return random.choice(bad) if bad else None
    weights=[]
    for r in pool:
        tag=(r.get("tag") or r.get("Tag") or "").strip().lower()
        weights.append(0.2 if tag in badtags else 1.0)
    try:
        return random.choices(pool, weights=weights, k=1)[0]
    except:
        return random.choice(pool)

# ------------------- Floors -------------------
def _ensure_floors(sig, wifi_pool, tls_pool, dev_pool):
    # ip_geo
    if "ip_geo" not in sig:
        sig["ip_geo"]={"ip":f"192.0.2.{random.randint(1,254)}"}

    # wifi + gps
    if "wifi_bssid" not in sig and wifi_pool:
        w=random.choice(wifi_pool); b=w.get("bssid") or w.get("BSSID")
        if b:
            sig["wifi_bssid"]={"bssid":str(b).lower()}
            lat=_to_float(w.get("lat") or w.get("Lat") or w.get("latitude"))
            lon=_to_float(w.get("lon") or w.get("Lon") or w.get("longitude"))
            if lat and lon:
                sig["gps"]={"lat":lat,"lon":lon}

    if "gps" not in sig:
        sig["gps"]={"lat":37.77+random.uniform(-0.1,0.1),
                    "lon":-122.41+random.uniform(-0.1,0.1)}

    # tls
    if "tls_fp" not in sig and tls_pool:
        r=_pick_tls_row(tls_pool, bad_only=False)
        if r and (r.get("ja3") or r.get("JA3")):
            sig["tls_fp"]={"ja3": r.get("ja3") or r.get("JA3")}

    # device
    if "device_posture" not in sig and dev_pool:
        d=random.choice(dev_pool)
        dev_id=d.get("device_id") or d.get("Device_ID") or d.get("deviceId") or f"dev-{random.randint(1,999)}"
        patched=str(d.get("patched","true")).strip().lower()=="true"
        sig["device_posture"]={"device_id":str(dev_id),"patched":patched}

# ------------------- STRIDE Scenario builders -------------------
def _make_spoofing(sig, wifi_pool):
    if "wifi_bssid" not in sig or not wifi_pool: return
    bssid=str(sig.get("wifi_bssid",{}).get("bssid") or "").lower()
    if not bssid: return
    w=next((x for x in wifi_pool if str(x.get("bssid") or x.get("BSSID")).lower()==bssid), None)
    if not w: return
    lat=_to_float(w.get("lat") or w.get("Lat") or w.get("latitude"))
    lon=_to_float(w.get("lon") or w.get("Lon") or w.get("longitude"))
    if lat is None or lon is None: return
    g_lat,g_lon=_offset_gps(lat,lon,GPS_OFFSET_KM)
    sig["gps"]={"lat":g_lat,"lon":g_lon}

# ------------------- Signal builder -------------------
def _mk_signals(row, wifi_row, tls_row, dev_row) -> Dict[str,Any]:
    sig={}
    sig["session_id"]=f"sess-{random.randrange(100000,999999)}"
    lab=row.get("Label") or row.get(" label") or row.get("LABEL")
    if lab: sig["label"]=str(lab).strip()
    src_ip=_get_src_ip(row)
    if src_ip: sig["ip_geo"]={"ip":src_ip}
    if wifi_row:
        b=wifi_row.get("bssid") or wifi_row.get("BSSID")
        if b: sig["wifi_bssid"]={"bssid":str(b).lower()}
        if USE_GPS_FROM_WIFI:
            lat=_to_float(wifi_row.get("lat") or wifi_row.get("Lat") or wifi_row.get("latitude"))
            lon=_to_float(wifi_row.get("lon") or wifi_row.get("Lon") or wifi_row.get("longitude"))
            if lat and lon: sig["gps"]={"lat":lat,"lon":lon}
    if dev_row:
        dev_id=dev_row.get("device_id") or dev_row.get("Device_ID") or dev_row.get("deviceId")
        if dev_id:
            patched_raw=str(dev_row.get("patched","true")).strip().lower()
            patched=True if patched_raw not in {"true","false"} else (patched_raw=="true")
            sig["device_posture"]={"device_id":str(dev_id),"patched":patched}
    if tls_row:
        ja3=tls_row.get("ja3") or tls_row.get("JA3")
        if ja3: sig["tls_fp"]={"ja3":str(ja3)}
    return sig

# ------------------- Post validate/decide -------------------
def _post_validate_and_decide(client, sig):
    try:
        vr=client.post(VALIDATE_URL,json={"signals":sig},timeout=10); vr.raise_for_status()
        validated=vr.json().get("validated",{})
    except Exception as e: return {"ok":False,"stage":"validate","error":str(e)}
    try:
        dr=client.post(GATEWAY_URL,json={"validated":validated,"siem":{}},timeout=10); dr.raise_for_status()
        return {"ok":True,**dr.json()}
    except Exception as e: return {"ok":False,"stage":"decision","error":str(e)}

# ------------------- Main -------------------
def main():
    cic_files=_list_csvs(CICIDS_DIR)
    if not cic_files: print(f"[sim] no CICIDS in {CICIDS_DIR}"); sys.exit(0)
    wifi_pool=_wifi_pool(); tls_pool=_tls_pool(); dev_pool=_dev_pool() or [{}]
    print(f"[sim] pools: wifi={len(wifi_pool)} tls={len(tls_pool)} device={len(dev_pool)}")

    rows=[]
    for f in cic_files:
        try:
            r=_read_csv(f); random.shuffle(r)
            attacks, benign=[],[]
            for x in r:
                lab=(x.get("Label") or x.get(" label") or "").strip().upper()
                if lab=="BENIGN":
                    if random.random()<BENIGN_KEEP: benign.append(x)
                else: attacks.append(x)
            rows.extend((attacks+benign)[:MAX_PER_FILE])
        except: pass
    random.shuffle(rows)

    # STRIDE buckets
    buckets=[("spoof",P_SPOOF),("tls",P_TLS),("dos",P_DOS),
             ("exfil",P_EXFIL),("eop",P_EOP),("rep",P_REP)]
    total=sum(p for _,p in buckets) or 1.0
    cum=[]; acc=0.0
    for k,p in buckets:
        acc+=p/total; cum.append((acc,k))

    sent=0
    with httpx.Client() as client:
        for row in rows:
            wifi_row=random.choice(wifi_pool) if wifi_pool else None
            tls_row=_pick_tls_row(tls_pool,bad_only=False) if tls_pool else None
            dev_row=random.choice(dev_pool) if dev_pool else None
            sig=_mk_signals(row,wifi_row,tls_row,dev_row)

            # assign bucket
            r=random.random(); bucket="spoof"
            for edge,k in cum:
                if r<=edge: bucket=k; break

            if bucket == "spoof":
                _make_spoofing(sig, wifi_pool)
                sig["label"] = "BENIGN"

            elif bucket == "tls":
                bad = _pick_tls_row(tls_pool, bad_only=True)
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

            _ensure_floors(sig,wifi_pool,tls_pool,dev_pool)

            out=_post_validate_and_decide(client,sig)
            print(json.dumps(out))
            time.sleep(SLEEP_BETWEEN); sent+=1
            if sent>=MAX_ROWS: break
    print("[sim] done")

if __name__=="__main__":
    main()
