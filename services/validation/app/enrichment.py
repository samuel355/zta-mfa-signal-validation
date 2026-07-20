from __future__ import annotations
import os, csv
from datetime import date
from typing import Dict, Any, Optional

PATH_GEOIP = os.getenv("PATH_GEOIP", "/data/geolite2/GeoLite2-City.mmdb")
PATH_WIFI  = os.getenv("PATH_WIFI",  "/data/wifi/wigle_sample.csv")
PATH_TLS   = os.getenv("PATH_TLS",   "/data/tls/ja3_fingerprints.csv")
PATH_DEV   = os.getenv("PATH_DEV",   "/data/device_posture/device_posture.csv")

DIST_THRESHOLD_KM = float(os.getenv("DIST_THRESHOLD_KM", "50"))

_geo_reader = None
_wifi_db: Dict[str, Dict[str, Any]] = {}
_tls_db:  Dict[str, str] = {}
_dev_db:  Dict[str, Dict[str, Any]] = {}
_dev_max_date: Optional[date] = None

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
            # JA3 itself is comma-separated and unquoted in this file, so a
            # plain csv.DictReader would split it wrong. Parse by hand: last
            # field is the tag, everything before it (rejoined) is the ja3 string.
            with open(PATH_TLS) as f:
                lines = [ln.rstrip("\n") for ln in f if ln.strip()]
            for line in lines[1:]:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 2: continue
                ja3, tag = ",".join(parts[:-1]), parts[-1]
                if ja3: _tls_db[ja3] = tag
            DATA_STATUS["tls"] = True
    except Exception:
        _tls_db = {}

def _load_dev():
    global _dev_db, _dev_max_date
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
            # Age is measured relative to the fleet's own freshest check-in,
            # not a live wall clock.
            dates = []
            for v in _dev_db.values():
                try:
                    dates.append(date.fromisoformat(str(v["last_update"])))
                except Exception:
                    pass
            if dates:
                _dev_max_date = max(dates)
    except Exception:
        _dev_db = {}

def _ensure_loaded():
    _load_geo(); _load_wifi(); _load_tls(); _load_dev()

def device_freshness(dev_id: str, window_days: float) -> float:
    """Fs for device_posture: linear decay from the fleet's freshest check-in.
    The other four signal types are read live and treated as fresh (Fs=1.0)."""
    _load_dev()
    d = _dev_db.get(dev_id or "", {})
    raw = d.get("last_update")
    if not raw or _dev_max_date is None or window_days <= 0:
        return 0.5  # no capture-time data to judge freshness by — neutral, not penalized
    try:
        this_date = date.fromisoformat(str(raw))
    except Exception:
        return 0.5
    age_days = (_dev_max_date - this_date).days
    return max(0.0, 1.0 - age_days / window_days)

def _os_family(os_str: Any) -> str:
    s = str(os_str or "").strip().lower()
    if "android" in s: return "android"
    if "ios" in s: return "ios"
    if "mac" in s: return "macos"
    if "windows" in s: return "windows"
    if any(k in s for k in ("ubuntu", "debian", "centos", "linux")): return "linux"
    return "unknown"

def device_tls_consistency(e: Dict[str, Any], mismatch_penalty: float) -> float:
    """Cs shared by device_posture and tls_fp: does the device's recorded OS
    agree with the TLS handshake's JA3-tagged platform? Only OS-specific tags
    (android_app, ios_app, safari_like) can contradict device_posture.os."""
    dev_os = _os_family((e.get("device") or {}).get("os"))
    tag = ((e.get("tls") or {}).get("tag") or "").strip().lower()
    if not tag or dev_os == "unknown":
        return 1.0
    if tag == "android_app":
        return 1.0 if dev_os == "android" else mismatch_penalty
    if tag == "ios_app":
        return 1.0 if dev_os == "ios" else mismatch_penalty
    if tag == "safari_like":
        return 1.0 if dev_os in ("macos", "ios") else mismatch_penalty
    return 1.0

def geo_consistency(e: Dict[str, Any], mismatch_penalty: float, key: Optional[str] = None) -> float:
    """Cs for gps/wifi_bssid/ip_geo: does this signal's implied location agree
    with the others within DIST_THRESHOLD_KM? `key` scopes the check to one
    pairwise distance; omitted, it takes the worst of all available."""
    checks = e.get("checks") or {}
    thr = checks.get("threshold_km", DIST_THRESHOLD_KM)
    keys = [key] if key else ["gps_wifi_distance_km", "gps_ip_distance_km"]
    scores = []
    for k in keys:
        d = checks.get(k)
        if isinstance(d, (int, float)):
            scores.append(1.0 if d <= thr else mismatch_penalty)
    return min(scores) if scores else 1.0

def enrichment_score(kind: str, e: Dict[str, Any], crit_tags: set, crit_penalty: float) -> float:
    """Es: did an authoritative external source corroborate this signal?
    gps is the anchor the others are cross-checked against, so it's fixed at 1.0."""
    if kind == "gps":
        return 1.0
    if kind == "ip_geo":
        geo = e.get("geo")
        return 1.0 if geo and geo.get("lat") is not None else 0.0
    if kind == "wifi_bssid":
        w = e.get("wifi")
        return 1.0 if w and w.get("lat") is not None else 0.0
    if kind == "device_posture":
        d = e.get("device")
        return 1.0 if d and d.get("os") else 0.0
    if kind == "tls_fp":
        tag = ((e.get("tls") or {}).get("tag") or "").strip().lower()
        if not tag:
            return 0.0
        return crit_penalty if tag in crit_tags else 1.0
    return 1.0

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
                checks["gps_wifi_distance_km"] = round(_haversine(a_lat, a_lon, b_lat, b_lon), 3)
            if "geo" in out and all(k in out["geo"] for k in ("lat","lon")):
                b_lat, b_lon = out["geo"]["lat"], out["geo"]["lon"]
                checks["gps_ip_distance_km"] = round(_haversine(a_lat, a_lon, b_lat, b_lon), 3)
            # Combined field for main.py's reasons/cross-check logic — prefers
            # wifi (tighter bound than IP geolocation), falls back to IP.
            if "gps_wifi_distance_km" in checks:
                checks["ip_wifi_distance_km"] = checks["gps_wifi_distance_km"]
            elif "gps_ip_distance_km" in checks:
                checks["ip_wifi_distance_km"] = checks["gps_ip_distance_km"]

    if checks:
        checks["threshold_km"] = DIST_THRESHOLD_KM
        out["checks"] = checks
    return out