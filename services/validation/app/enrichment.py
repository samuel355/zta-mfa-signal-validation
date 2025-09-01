# services/validation/app/enrichment.py
from __future__ import annotations

import os, csv, json
from typing import Dict, Any

# ---------- File locations (can be overridden via env) ----------
PATH_GEOIP = os.getenv("PATH_GEOIP", "/data/geolite2/GeoLite2-City.mmdb")
PATH_WIFI  = os.getenv("PATH_WIFI",  "/data/wifi/wigle_sample.csv")
PATH_TLS   = os.getenv("PATH_TLS",   "/data/tls/ja3_fingerprints.csv")
PATH_DEV   = os.getenv("PATH_DEV",   "/data/device_posture/device_posture.csv")

# ---------- Loaders (lazy; safe if files don’t exist) ----------
_geo_reader = None
_wifi_db: Dict[str, Dict[str, Any]] = {}
_tls_db:  Dict[str, str] = {}
_dev_db:  Dict[str, Dict[str, Any]] = {}

DATA_STATUS = {
    "geoip": False,
    "wifi":  False,
    "tls":   False,
    "device":False,
}

def _load_geo():
    global _geo_reader
    if _geo_reader is not None:
        return
    try:
        import geoip2.database
        if os.path.isfile(PATH_GEOIP):
            _geo_reader = geoip2.database.Reader(PATH_GEOIP)
            DATA_STATUS["geoip"] = True
    except Exception:
        _geo_reader = None

def _load_wifi():
    global _wifi_db
    if _wifi_db:
        return
    try:
        if os.path.isfile(PATH_WIFI):
            with open(PATH_WIFI, newline="") as f:
                for row in csv.DictReader(f):
                    bssid = (row.get("bssid") or "").lower()
                    if not bssid:
                        continue
                    _wifi_db[bssid] = {
                        "ssid": row.get("ssid"),
                        "lat": float(row["lat"]),
                        "lon": float(row["lon"]),
                    }
            DATA_STATUS["wifi"] = True
    except Exception:
        _wifi_db = {}

def _load_tls():
    global _tls_db
    if _tls_db:
        return
    try:
        if os.path.isfile(PATH_TLS):
            with open(PATH_TLS, newline="") as f:
                for row in csv.DictReader(f):
                    ja3 = (row.get("ja3") or "").strip()
                    if not ja3:
                        continue
                    _tls_db[ja3] = row.get("tag") or ""
            DATA_STATUS["tls"] = True
    except Exception:
        _tls_db = {}

def _load_dev():
    global _dev_db
    if _dev_db:
        return
    try:
        if os.path.isfile(PATH_DEV):
            with open(PATH_DEV, newline="") as f:
                for row in csv.DictReader(f):
                    dev_id = row.get("device_id")
                    if not dev_id:
                        continue
                    _dev_db[dev_id] = {
                        "os": row.get("os"),
                        "patched": str(row.get("patched", "")).lower() == "true",
                        "edr": row.get("edr"),
                        "last_update": row.get("last_update"),
                    }
            DATA_STATUS["device"] = True
    except Exception:
        _dev_db = {}

def _ensure_loaded():
    _load_geo(); _load_wifi(); _load_tls(); _load_dev()

# ---------- Single-signal enrich helpers ----------
def enrich_ip(ip: str) -> Dict[str, Any]:
    _load_geo()
    if not _geo_reader:
        return {}
    try:
        r = _geo_reader.city(ip)
        return {
            "country": r.country.iso_code,
            "city":    r.city.name,
            "lat":     r.location.latitude,
            "lon":     r.location.longitude,
        }
    except Exception:
        return {}

def enrich_wifi(bssid: str) -> Dict[str, Any]:
    _load_wifi()
    return _wifi_db.get((bssid or "").lower(), {})

def enrich_tls(ja3: str) -> Dict[str, Any]:
    _load_tls()
    tag = _tls_db.get(ja3 or "")
    return {"tag": tag} if tag else {}

def enrich_device(dev_id: str) -> Dict[str, Any]:
    _load_dev()
    return _dev_db.get(dev_id or "", {})

# ---------- Public: enrich the full signals payload ----------
def enrich_all(signals: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns {
      "geo": {...}, "wifi": {...}, "tls": {...}, "device": {...},
      "checks": { "ip_wifi_distance_km": <float>|None }
    }
    """
    _ensure_loaded()
    out: Dict[str, Any] = {}
    # ip -> geo
    ip = (signals.get("ip_geo") or {}).get("ip")
    if ip:
        out["geo"] = enrich_ip(ip)

    # wifi -> location + consistency check vs ip_geo/gps
    bssid = (signals.get("wifi_bssid") or {}).get("bssid")
    if bssid:
        w = enrich_wifi(bssid)
        if w:
            out["wifi"] = w

    # tls -> tag
    ja3 = (signals.get("tls_fp") or {}).get("ja3")
    if ja3:
        t = enrich_tls(ja3)
        if t:
            out["tls"] = t

    # device posture
    dev_id = (signals.get("device_posture") or {}).get("device_id")
    if dev_id:
        d = enrich_device(dev_id)
        if d:
            out["device"] = d

    # simple cross-check: geodistance between gps vs wifi/geo (if both exist)
    def _haversine(a_lat, a_lon, b_lat, b_lon):
        from math import radians, sin, cos, asin, sqrt
        R = 6371.0
        dlat = radians(b_lat - a_lat)
        dlon = radians(b_lon - a_lon)
        A = sin(dlat/2)**2 + cos(radians(a_lat))*cos(radians(b_lat))*sin(dlon/2)**2
        return 2*R*asin(sqrt(A))

    checks = {}
    gps = signals.get("gps") or {}
    g1 = (gps.get("lat"), gps.get("lon")) if all(k in gps for k in ("lat","lon")) else None

    # prefer wifi vs gps, else ipgeo vs gps
    if g1:
        if "wifi" in out:
            g2 = (out["wifi"]["lat"], out["wifi"]["lon"])
            checks["ip_wifi_distance_km"] = round(_haversine(g1[0], g1[1], g2[0], g2[1]), 3)
        elif "geo" in out and all(k in out["geo"] for k in ("lat","lon")):
            g2 = (out["geo"]["lat"], out["geo"]["lon"])
            checks["ip_wifi_distance_km"] = round(_haversine(g1[0], g1[1], g2[0], g2[1]), 3)

    if checks:
        out["checks"] = checks
    return out