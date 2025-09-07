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

SLEEP_BETWEEN = float(os.getenv("SIM_SLEEP", "0.8"))
MAX_ROWS      = int(os.getenv("SIM_MAX_ROWS", "300"))
MAX_PER_FILE  = int(os.getenv("SIM_MAX_PER_FILE", "500"))
USE_GPS_FROM_WIFI = os.getenv("SIM_USE_GPS_FROM_WIFI","false").lower() in {"1","true","yes","on"}

def _ef(name, default):
    try: v=os.getenv(name,"").strip(); return float(v) if v else default
    except: return default

MIN_WIFI   = _ef("SIM_MIN_WIFI", 0.0)
MIN_GPS    = _ef("SIM_MIN_GPS",  0.0)
MIN_TLS    = _ef("SIM_MIN_TLS",  0.0)
MIN_DEVICE = _ef("SIM_MIN_DEVICE",0.0)

INJECT_GPS_MISMATCH = _ef("SIM_INJECT_GPS_MISMATCH", 0.30)
TLS_BAD_RATE        = _ef("SIM_TLS_BAD_RATE",        0.15)
PATCHED_TRUE_RATE   = _ef("SIM_PATCHED_TRUE_RATE",   0.70)
GPS_OFFSET_KM       = _ef("SIM_GPS_OFFSET_KM",       400.0)

SIM_MODE = os.getenv("SIM_MODE","balanced").lower()
PCT_SPOOF   = _ef("SIM_PCT_SPOOFING",      0.22)
PCT_TLS     = _ef("SIM_PCT_TLS_TAMPERING", 0.18)
PCT_DOS     = _ef("SIM_PCT_DOS",           0.20)
PCT_EXFIL   = _ef("SIM_PCT_EXFIL",         0.20)
PCT_EOP     = _ef("SIM_PCT_EOP",           0.20)

def _to_float(x)->Optional[float]:
    try: return float(str(x).strip())
    except: return None

def _read_csv(path: str)->List[Dict[str,Any]]:
    with open(path, newline="") as f: return list(csv.DictReader(f))

def _list_csvs(dirpath: str)->List[str]:
    return [os.path.join(dirpath, f) for f in os.listdir(dirpath) if f.endswith(".csv")]

def _wifi_rows() -> List[Dict[str, Any]]:
    """
    Load Wi-Fi rows robustly.
    Accept header variants for BSSID: bssid, BSSID, mac, MAC, 'BSSID/MAC'.
    Accept lat/lon variants: lat, Lat, latitude  / lon, Lon, longitude
    If no BSSID but lat/lon exist, fabricate a deterministic pseudo-BSSID so
    the simulator can still emit wifi_bssid and GPS-from-WiFi.
    """
    out: List[Dict[str, Any]] = []
    path = WIFI_CSV
    try:
        rows = _read_csv(path)
        for i, r in enumerate(rows):
            # lat/lon parsing (required for usefulness)
            lat = _to_float(r.get("lat") or r.get("Lat") or r.get("latitude"))
            lon = _to_float(r.get("lon") or r.get("Lon") or r.get("longitude"))
            if lat is None or lon is None:
                continue

            # try to find a BSSID-ish field
            bssid = (
                r.get("bssid") or r.get("BSSID") or
                r.get("mac") or r.get("MAC") or
                r.get("BSSID/MAC") or r.get("bssid_mac")
            )
            if bssid:
                bssid = str(bssid).strip().lower()
            else:
                # fabricate a stable pseudo-bssid from lat/lon buckets
                # (keeps sessions consistent but obviously synthetic)
                import hashlib
                h = hashlib.md5(f"{lat:.4f},{lon:.4f}".encode()).hexdigest()
                bssid = f"fa:ke:{h[0:2]}:{h[2:4]}:{h[4:6]}:{h[6:8]}"

            out.append({"bssid": bssid, "lat": lat, "lon": lon})
    except Exception as e:
        print(f"[sim] wifi load failed from {path}: {e!s}")
        out = []

    # tiny log so we can see it loaded
    print(f"[sim] wifi rows loaded: {len(out)} from {path}")
    return out

def _device_rows():
    try: return _read_csv(DEVICE_CSV)
    except: return []

def _tls_rows():
    try: return _read_csv(TLS_CSV)
    except: return []

def _label_of(row: Dict[str,Any])->str:
    lab = row.get("Label") or row.get(" label") or row.get("LABEL") or ""
    return str(lab).strip().upper()

def _families_for_row(row: Dict[str,Any])->str:
    L = _label_of(row)
    if not L or L == "BENIGN": return "BENIGN"
    if ("DDOS" in L) or L.startswith("DOS") or ("PORTSCAN" in L): return "DOS"
    if ("WEB ATTACK" in L) or ("SQLI" in L) or ("XSS" in L):     return "EOP"
    if ("BOT" in L) or ("INFILTRATION" in L):                    return "EXFIL"
    if ("HEARTBLEED" in L):                                      return "TLS"
    return "OTHER"

def _stratify(rows: List[Dict[str,Any]]):
    b = {"BENIGN":[], "DOS":[], "EOP":[], "EXFIL":[], "TLS":[], "OTHER":[]}
    for r in rows: b[_families_for_row(r)].append(r)
    return b

def _offset_gps(lat: float, lon: float, km: float)->tuple[float,float]:
    from math import radians, cos
    dlat = km/111.0
    dlon = (km / (111.0*max(0.1,cos(radians(lat))))) * (1 if random.random()<0.5 else -1)
    return lat + (dlat if random.random()<0.5 else -dlat), lon + dlon

def _weighted_tls_choice(rows: List[Dict[str, Any]]):
    if not rows: return None
    weights=[]
    for r in rows:
        tag = (r.get("tag") or r.get("Tag") or "").strip().lower()
        weights.append(0.2 if tag in {
            "tor_suspect","malware_family_x","scanner_tool","cloud_proxy","old_openssl","insecure_client","honeypot_fingerprint"
        } else 1.0)
    try: return random.choices(rows, weights=weights, k=1)[0]
    except: return random.choice(rows)

def _make_tls(sig, tls_pool):
    if not tls_pool: return
    if random.random() < TLS_BAD_RATE:
        bad = [r for r in tls_pool if (r.get("tag") or r.get("Tag") or "").strip().lower() in {
            "tor_suspect","malware_family_x","scanner_tool","cloud_proxy","old_openssl","insecure_client","honeypot_fingerprint"}]
        if bad:
            row = random.choice(bad); ja3 = row.get("ja3") or row.get("JA3")
            if ja3: sig["tls_fp"]={"ja3":str(ja3)}; return
    row = _weighted_tls_choice(tls_pool)
    if row:
        ja3 = row.get("ja3") or row.get("JA3")
        if ja3: sig["tls_fp"]={"ja3":str(ja3)}

def _ensure_floors(sig, row, wifi_pool, tls_pool, dev_pool):
    if "ip_geo" not in sig:
        for k in ("Src IP"," Source IP","Src_IP","src_ip"," Source IP "):
            if row.get(k): sig["ip_geo"]={"ip":str(row[k]).strip()}; break
    if "wifi_bssid" not in sig and wifi_pool and random.random() < MIN_WIFI:
        w = random.choice(wifi_pool); b = w.get("bssid") or w.get("BSSID")
        if b:
            sig["wifi_bssid"]={"bssid":str(b).lower()}
            if USE_GPS_FROM_WIFI and "gps" not in sig:
                lat=w.get("lat") or w.get("Lat") or w.get("latitude")
                lon=w.get("lon") or w.get("Lon") or w.get("longitude")
                try:
                    if lat not in (None,"") and lon not in (None,""):
                        sig["gps"]={"lat":float(lat),"lon":float(lon)}
                except: pass
    if "gps" not in sig and USE_GPS_FROM_WIFI and "wifi_bssid" in sig and random.random() < MIN_GPS:
        bssid = sig["wifi_bssid"]["bssid"]
        w = next((x for x in wifi_pool if str(x.get("bssid") or x.get("BSSID")).lower()==bssid), None)
        if w:
            lat=w.get("lat") or w.get("Lat") or w.get("latitude")
            lon=w.get("lon") or w.get("Lon") or w.get("longitude")
            try: sig["gps"]={"lat":float(lat),"lon":float(lon)}
            except: pass
    if "tls_fp" not in sig and tls_pool and random.random() < MIN_TLS:
        r = random.choice(tls_pool); ja3 = r.get("ja3") or r.get("JA3")
        if ja3: sig["tls_fp"]={"ja3":str(ja3)}
    if "device_posture" not in sig and dev_pool and random.random() < MIN_DEVICE:
        d = random.choice(dev_pool)
        dev_id = d.get("device_id") or d.get("Device_ID") or d.get("deviceId")
        if dev_id:
            ps = str(d.get("patched","")).strip().lower()
            patched = True if ps not in {"true","false"} else (ps=="true")
            sig["device_posture"]={"device_id":str(dev_id),"patched":patched}

def _make_spoofing(sig: Dict[str, Any], wifi_pool: List[Dict[str, Any]]):
    """Inject GPS spoofing relative to Wi-Fi."""
    if "gps" in sig or "wifi_bssid" not in sig or random.random() >= INJECT_GPS_MISMATCH:
        return
    try:
        # pick a Wi-Fi row that actually has lat/lon
        w = None
        for cand in wifi_pool:
            latf = _to_float(cand.get("lat") or cand.get("Lat") or cand.get("latitude"))
            lonf = _to_float(cand.get("lon") or cand.get("Lon") or cand.get("longitude"))
            if latf is not None and lonf is not None:
                w = cand
                break
        if not w:
            return
        latf = _to_float(w.get("lat") or w.get("Lat") or w.get("latitude"))
        lonf = _to_float(w.get("lon") or w.get("Lon") or w.get("longitude"))
        if latf is None or lonf is None:
            return
        g_lat, g_lon = _offset_gps(latf, lonf, GPS_OFFSET_KM)
        sig["gps"] = {"lat": g_lat, "lon": g_lon}
    except Exception:
        pass

def _mk_signals(
    row: Dict[str, Any],
    wifi_row: Optional[Dict[str, Any]],
    tls_row: Optional[Dict[str, Any]],
    dev_row: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    sig: Dict[str, Any] = {}
    sig["session_id"] = f"sess-{random.randrange(100000, 999999)}"

    # Label (from CICIDS)
    lab = row.get("Label") or row.get(" label") or row.get("LABEL")
    if lab is not None:
        sig["label"] = str(lab).strip()

    # IP
    src_ip = (
        row.get("Src IP") or row.get(" Source IP") or
        row.get("Src_IP") or row.get("src_ip")
    )
    if src_ip:
        sig["ip_geo"] = {"ip": str(src_ip).strip()}

    # Wi-Fi (plus GPS from Wi-Fi if available & enabled)
    if wifi_row:
        bssid = wifi_row.get("bssid") or wifi_row.get("BSSID")
        if bssid:
            sig["wifi_bssid"] = {"bssid": str(bssid).lower()}

        lat = wifi_row.get("lat") or wifi_row.get("Lat") or wifi_row.get("latitude")
        lon = wifi_row.get("lon") or wifi_row.get("Lon") or wifi_row.get("longitude")
        latf, lonf = _to_float(lat), _to_float(lon)
        if latf is not None and lonf is not None and USE_GPS_FROM_WIFI and "gps" not in sig:
            sig["gps"] = {"lat": latf, "lon": lonf}

    # Device posture (with patched-bias)
    if dev_row:
        dev_id = dev_row.get("device_id") or dev_row.get("Device_ID") or dev_row.get("deviceId")
        if dev_id:
            patched_s = str(dev_row.get("patched", "")).strip().lower()
            if patched_s in {"true", "false"}:
                patched = (patched_s == "true")
            else:
                patched = True  # default true if dataset lacks explicit value
            if random.random() < PATCHED_TRUE_RATE:
                patched = True
            sig["device_posture"] = {"device_id": str(dev_id), "patched": patched}

    # TLS JA3
    if tls_row:
        ja3 = tls_row.get("ja3") or tls_row.get("JA3")
        if ja3:
            sig["tls_fp"] = {"ja3": str(ja3)}

    return sig

def _post_validate_and_decide(client, signals):
    try:
        vr = client.post(VALIDATE_URL, json={"signals": signals}, timeout=10.0); vr.raise_for_status()
        validated = vr.json().get("validated", {})
    except Exception as e:
        return {"ok": False, "stage":"validate", "error": str(e)}
    try:
        dr = client.post(GATEWAY_URL, json={"validated": validated, "siem": {}}, timeout=10.0); dr.raise_for_status()
        return {"ok": True, **dr.json()}
    except Exception as e:
        return {"ok": False, "stage":"decision", "error": str(e)}

def main():
    cic_files = _list_csvs(CICIDS_DIR)
    if not cic_files:
        print(f"[sim] no CICIDS CSVs in {CICIDS_DIR}"); sys.exit(0)

    wifi_pool = _wifi_rows()
    tls_pool  = _tls_rows()
    dev_pool  = _device_rows() or [{}]
    print(f"[sim] pools: wifi={len(wifi_pool)} tls={len(tls_pool)} device={len(dev_pool)}")
    if len(wifi_pool) == 0:
        print("[sim] FATAL: wifi_pool is empty; check data/wifi/wigle_sample.csv (needs bssid,lat,lon). Aborting.")
        sys.exit(1)

    raw_rows=[]
    for f in cic_files:
        try:
            rows=_read_csv(f); random.shuffle(rows); raw_rows.extend(rows[:MAX_PER_FILE])
        except Exception: pass
    random.shuffle(raw_rows)

    buckets=_stratify(raw_rows)
    selected=[]; N=MAX_ROWS

    if SIM_MODE=="balanced":
        tgt = {
            "SPOOF": int(N*PCT_SPOOF), "TLS": int(N*PCT_TLS),
            "DOS": int(N*PCT_DOS), "EXFIL": int(N*PCT_EXFIL), "EOP": int(N*PCT_EOP)
        }
        selected += random.sample(buckets["TLS"],   min(tgt["TLS"],   len(buckets["TLS"])))
        selected += random.sample(buckets["DOS"],   min(tgt["DOS"],   len(buckets["DOS"])))
        selected += random.sample(buckets["EXFIL"], min(tgt["EXFIL"], len(buckets["EXFIL"])))
        selected += random.sample(buckets["EOP"],   min(tgt["EOP"],   len(buckets["EOP"])))
        selected += random.sample(buckets["BENIGN"],min(tgt["SPOOF"], len(buckets["BENIGN"])))
        if len(selected) < N:
            rest = [r for k,v in buckets.items() for r in v if r not in selected]
            random.shuffle(rest); selected += rest[:N-len(selected)]
        selected = selected[:N]
    else:
        selected = raw_rows[:N]

    sent=0
    with httpx.Client() as client:
        for row in selected:
            wifi_row = random.choice(wifi_pool) if wifi_pool else None
            tls_row  = _weighted_tls_choice(tls_pool) if tls_pool else None
            dev_row  = random.choice(dev_pool) if dev_pool else None

            sig=_mk_signals(row, wifi_row, tls_row, dev_row)
            _ensure_floors(sig, row, wifi_pool, tls_pool, dev_pool)
            _make_spoofing(sig, wifi_pool)

            if not any(k in sig for k in ("ip_geo","wifi_bssid","tls_fp","device_posture")): continue
            out = _post_validate_and_decide(client, sig)
            print(json.dumps(out))
            time.sleep(SLEEP_BETWEEN * random.uniform(0.8,1.3))

            sent += 1
            if sent >= MAX_ROWS: break

    print("[sim] done")

if __name__=="__main__":
    main()