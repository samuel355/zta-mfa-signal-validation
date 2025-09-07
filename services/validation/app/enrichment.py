from __future__ import annotations
import os, csv
from typing import Dict, Any

PATH_GEOIP = os.getenv("PATH_GEOIP", "/data/geolite2/GeoLite2-City.mmdb")
PATH_WIFI  = os.getenv("PATH_WIFI",  "/data/wifi/wigle_sample.csv")
PATH_TLS   = os.getenv("PATH_TLS",   "/data/tls/ja3_fingerprints.csv")
PATH_DEV   = os.getenv("PATH_DEV",   "/data/device_posture/device_posture.csv")

DIST_THRESHOLD_KM = float(os.getenv("DIST_THRESHOLD_KM", "50"))

_geo_reader = None
_wifi_db: Dict[str, Dict[str, Any]] = {}
_tls_db:  Dict[str, str] = {}
_dev_db:  Dict[str, Dict[str, Any]] = {}

DATA_STATUS = {"geoip": False, "wifi": False, "tls": False, "device": False}

def _load_geo():
    global _geo_reader
    if _geo_reader is not None: return
    try:
        import geoip2.database
        if os.path.isfile(PATH_GEOIP):
            _geo_reader = geoip2.database.Reader(PATH_GEOIP)
            DATA_STATUS["geoip"] = True
    except Exception:
        _geo_reader = None

def _to_float(x):
    try: return float(str(x).strip())
    except Exception: return None

def _load_wifi():
    global _wifi_db
    if _wifi_db: return
    try:
        if os.path.isfile(PATH_WIFI):
            with open(PATH_WIFI, newline="") as f:
                for row in csv.DictReader(f):
                    bssid = (row.get("bssid") or row.get("BSSID") or "").lower().strip()
                    if not bssid: continue
                    lat = _to_float(row.get("lat") or row.get("Lat") or row.get("latitude"))
                    lon = _to_float(row.get("lon") or row.get("Lon") or row.get("longitude"))
                    if lat is None or lon is None: continue
                    _wifi_db[bssid] = {"ssid": row.get("ssid") or row.get("SSID"), "lat": lat, "lon": lon}
            DATA_STATUS["wifi"] = True
    except Exception:
        _wifi_db = {}

def _load_tls():
    global _tls_db
    if _tls_db: return
    try:
        if os.path.isfile(PATH_TLS):
            with open(PATH_TLS, newline="") as f:
                for row in csv.DictReader(f):
                    ja3 = (row.get("ja3") or row.get("JA3") or "").strip()
                    if not ja3: continue
                    _tls_db[ja3] = (row.get("tag") or row.get("Tag") or "").strip()
            DATA_STATUS["tls"] = True
    except Exception:
        _tls_db = {}

def _load_dev():
    global _dev_db
    if _dev_db: return
    try:
        if os.path.isfile(PATH_DEV):
            with open(PATH_DEV, newline="") as f:
                for row in csv.DictReader(f):
                    dev_id = (row.get("device_id") or row.get("Device_ID") or row.get("deviceId"))
                    if not dev_id: continue
                    _dev_db[dev_id] = {
                        "os": row.get("os") or row.get("OS"),
                        "patched": str(row.get("patched", "")).strip().lower() == "true",
                        "edr": row.get("edr"),
                        "last_update": row.get("last_update"),
                    }
            DATA_STATUS["device"] = True
    except Exception:
        _dev_db = {}

def _ensure_loaded():
    _load_geo(); _load_wifi(); _load_tls(); _load_dev()

def enrich_ip(ip: str) -> Dict[str, Any]:
    _load_geo()
    if not _geo_reader: return {}
    try:
        r = _geo_reader.city(ip)
        return {"country": r.country.iso_code, "city": r.city.name, "lat": r.location.latitude, "lon": r.location.longitude}
    except Exception:
        return {}

def enrich_wifi(bssid: str) -> Dict[str, Any]:
    _load_wifi(); return _wifi_db.get((bssid or "").lower().strip(), {})

def enrich_tls(ja3: str) -> Dict[str, Any]:
    _load_tls(); tag = _tls_db.get(ja3 or "")
    return {"tag": tag} if tag else {}

def enrich_device(dev_id: str) -> Dict[str, Any]:
    _load_dev(); return _dev_db.get(dev_id or "", {})

def enrich_all(signals: Dict[str, Any]) -> Dict[str, Any]:
    _ensure_loaded()
    out: Dict[str, Any] = {}

    ip = (signals.get("ip_geo") or {}).get("ip")
    if ip:
        geo = enrich_ip(ip)
        if geo: out["geo"] = geo

    bssid = (signals.get("wifi_bssid") or {}).get("bssid")
    if bssid:
        w = enrich_wifi(bssid)
        if w: out["wifi"] = w

    ja3 = (signals.get("tls_fp") or {}).get("ja3")
    if ja3:
        t = enrich_tls(ja3)
        if t: out["tls"] = t

    dev_id = (signals.get("device_posture") or {}).get("device_id")
    if dev_id:
        d = enrich_device(dev_id)
        if d: out["device"] = d

    def _haversine(a_lat, a_lon, b_lat, b_lon):
        from math import radians, sin, cos, asin, sqrt
        R = 6371.0
        dlat = radians(b_lat - a_lat); dlon = radians(b_lon - a_lon)
        A = sin(dlat/2)**2 + cos(radians(a_lat))*cos(radians(b_lat))*sin(dlon/2)**2
        return 2*R*asin(sqrt(A))

    checks = {}
    gps = signals.get("gps") or {}
    if all(k in gps for k in ("lat","lon")):
        a_lat = _to_float(gps["lat"]); a_lon = _to_float(gps["lon"])
        if a_lat is not None and a_lon is not None:
            if "wifi" in out:
                b_lat, b_lon = out["wifi"]["lat"], out["wifi"]["lon"]
                checks["ip_wifi_distance_km"] = round(_haversine(a_lat, a_lon, b_lat, b_lon), 3)
            elif "geo" in out and all(k in out["geo"] for k in ("lat","lon")):
                b_lat, b_lon = out["geo"]["lat"], out["geo"]["lon"]
                checks["ip_wifi_distance_km"] = round(_haversine(a_lat, a_lon, b_lat, b_lon), 3)

    if checks:
        checks["threshold_km"] = DIST_THRESHOLD_KM
        out["checks"] = checks
    return out