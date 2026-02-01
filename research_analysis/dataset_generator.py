"""
Dataset Generator for Zero Trust MFA Parameter Optimization
============================================================

Generates realistic synthetic authentication sessions with various attack patterns
for comprehensive parameter optimization and validation.

Author: Research Team
Date: 2024
"""

import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd


@dataclass
class AuthSession:
    """Represents a single authentication session with all signals"""

    session_id: str
    timestamp: datetime
    user_id: str
    is_attack: bool
    attack_type: Optional[str]

    # Signal data
    gps_lat: float
    gps_lon: float
    gps_timestamp: datetime
    gps_accuracy: float

    ip_address: str
    ip_lat: float
    ip_lon: float
    ip_timestamp: datetime
    ip_country: str
    ip_asn: str

    device_id: str
    device_os: str
    device_os_version: str
    device_last_scan: datetime
    device_compliance_score: float
    device_av_status: bool
    device_encryption: bool

    wifi_bssid: Optional[str]
    wifi_ssid: Optional[str]
    wifi_timestamp: Optional[datetime]
    wifi_signal_strength: Optional[float]

    tls_fingerprint: str
    tls_timestamp: datetime
    tls_cipher_suite: str
    tls_version: str

    # Threat intelligence
    ip_is_vpn: bool
    ip_is_tor: bool
    ip_is_malicious: bool
    ip_reputation_score: float

    # SIEM alerts
    siem_alerts_high: int
    siem_alerts_medium: int
    siem_alerts_low: int

    # Ground truth
    true_location_lat: float
    true_location_lon: float
    legitimate_device: bool


class DatasetGenerator:
    """Generate realistic authentication sessions for optimization"""

    def __init__(self, seed: int = 42):
        """
        Initialize the dataset generator

        Args:
            seed: Random seed for reproducibility
        """
        np.random.seed(seed)
        random.seed(seed)

        # Define realistic geographic regions for legitimate users
        self.legitimate_regions = [
            {"name": "New York", "lat": 40.7128, "lon": -74.0060, "radius_km": 50},
            {"name": "London", "lat": 51.5074, "lon": -0.1278, "radius_km": 40},
            {"name": "Tokyo", "lat": 35.6762, "lon": 139.6503, "radius_km": 60},
            {
                "name": "San Francisco",
                "lat": 37.7749,
                "lon": -122.4194,
                "radius_km": 45,
            },
            {"name": "Berlin", "lat": 52.5200, "lon": 13.4050, "radius_km": 35},
            {"name": "Singapore", "lat": 1.3521, "lon": 103.8198, "radius_km": 30},
            {"name": "Sydney", "lat": -33.8688, "lon": 151.2093, "radius_km": 50},
            {"name": "Toronto", "lat": 43.6532, "lon": -79.3832, "radius_km": 40},
        ]

        # Device profiles
        self.device_types = [
            {"os": "Windows", "versions": ["10", "11"], "browser_fp": "win_chrome"},
            {
                "os": "macOS",
                "versions": ["12.0", "13.0", "14.0"],
                "browser_fp": "mac_safari",
            },
            {
                "os": "Linux",
                "versions": ["Ubuntu 22.04", "Fedora 38"],
                "browser_fp": "linux_firefox",
            },
            {"os": "iOS", "versions": ["16.0", "17.0"], "browser_fp": "ios_safari"},
            {
                "os": "Android",
                "versions": ["12", "13", "14"],
                "browser_fp": "android_chrome",
            },
        ]

        # TLS configurations
        self.tls_configs = [
            {"version": "TLS 1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
            {"version": "TLS 1.3", "cipher": "TLS_CHACHA20_POLY1305_SHA256"},
            {"version": "TLS 1.2", "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
        ]

        # WiFi networks (simulate known good networks)
        self.wifi_networks = [
            {"ssid": "CorporateWiFi", "bssid": "00:11:22:33:44:55"},
            {"ssid": "HomeNetwork", "bssid": "AA:BB:CC:DD:EE:FF"},
            {"ssid": "Starbucks", "bssid": "12:34:56:78:9A:BC"},
            {"ssid": "Airport_Free", "bssid": "DE:AD:BE:EF:CA:FE"},
        ]

        # IP ASN pools
        self.legitimate_asns = [
            "AS15169 (Google)",
            "AS8075 (Microsoft)",
            "AS7922 (Comcast)",
            "AS20940 (Akamai)",
            "AS16509 (Amazon)",
            "AS13335 (Cloudflare)",
        ]

        self.vpn_asns = [
            "AS9009 (M247 - VPN)",
            "AS63949 (Linode - VPN)",
            "AS51167 (Contabo - VPN)",
        ]

        self.malicious_asns = ["AS12345 (Known Botnet)", "AS99999 (Suspicious Hosting)"]

    def generate_dataset(
        self,
        n_sessions: int = 5000,
        attack_ratio: float = 0.20,
        attack_distribution: Dict[str, float] = None,
    ) -> pd.DataFrame:
        """
        Generate comprehensive dataset with legitimate and attack sessions

        Args:
            n_sessions: Total number of sessions to generate
            attack_ratio: Proportion of attack sessions (0.0-1.0)
            attack_distribution: Distribution of attack types
                - 'geo_spoof': Geographic location spoofing
                - 'stale_data': Using stale/cached credentials
                - 'device_compromise': Compromised device access
                - 'network_manipulation': Network-level attacks (VPN/TOR)

        Returns:
            DataFrame with all session data
        """
        if attack_distribution is None:
            attack_distribution = {
                "geo_spoof": 0.40,
                "stale_data": 0.30,
                "device_compromise": 0.20,
                "network_manipulation": 0.10,
            }

        sessions = []
        n_attacks = int(n_sessions * attack_ratio)
        n_legitimate = n_sessions - n_attacks

        # Generate legitimate sessions
        print(f"Generating {n_legitimate} legitimate sessions...")
        for i in range(n_legitimate):
            session = self._generate_legitimate_session(f"LEG_{i:06d}")
            sessions.append(session)

        # Generate attack sessions
        print(f"Generating {n_attacks} attack sessions...")
        attack_types = list(attack_distribution.keys())
        attack_probs = list(attack_distribution.values())

        for i in range(n_attacks):
            attack_type = np.random.choice(attack_types, p=attack_probs)
            session = self._generate_attack_session(f"ATK_{i:06d}", attack_type)
            sessions.append(session)

        # Convert to DataFrame
        df = self._sessions_to_dataframe(sessions)

        # Shuffle the dataset
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)

        print(f"\nDataset generated successfully!")
        print(f"Total sessions: {len(df)}")
        print(
            f"Legitimate: {len(df[~df['is_attack']])} ({100 * (1 - attack_ratio):.1f}%)"
        )
        print(f"Attacks: {len(df[df['is_attack']])} ({100 * attack_ratio:.1f}%)")
        print(f"\nAttack type distribution:")
        for attack_type in attack_types:
            count = len(df[df["attack_type"] == attack_type])
            print(f"  {attack_type}: {count} ({100 * count / n_attacks:.1f}%)")

        return df

    def _generate_legitimate_session(self, session_id: str) -> AuthSession:
        """Generate a realistic legitimate authentication session"""

        # Select a home region for this user
        region = random.choice(self.legitimate_regions)

        # Generate true location (within region)
        true_lat, true_lon = self._random_location_in_radius(
            region["lat"], region["lon"], region["radius_km"]
        )

        # Generate timestamps (all recent, within freshness windows)
        base_time = datetime.now() - timedelta(seconds=random.randint(0, 300))

        # GPS data - slightly offset from true location (GPS error)
        gps_lat, gps_lon = self._add_location_noise(
            true_lat, true_lon, 0.01
        )  # ~1km error
        gps_timestamp = base_time - timedelta(
            seconds=random.randint(0, 180)
        )  # Within 3 min
        gps_accuracy = random.uniform(5, 50)  # meters

        # IP geolocation - less accurate, same general area
        ip_lat, ip_lon = self._add_location_noise(
            true_lat, true_lon, 0.1
        )  # ~10km error
        ip_timestamp = base_time - timedelta(
            seconds=random.randint(0, 400)
        )  # Within ~7 min
        ip_address = self._generate_ip_address(region["name"])

        # Device data - compliant and up-to-date
        device = random.choice(self.device_types)
        device_id = f"DEV_{random.randint(100000, 999999)}"
        device_last_scan = base_time - timedelta(hours=random.randint(1, 20))
        device_compliance_score = random.uniform(0.85, 1.0)

        # WiFi data - may or may not be present
        wifi_present = random.random() < 0.7  # 70% have WiFi
        if wifi_present:
            wifi_net = random.choice(self.wifi_networks)
            wifi_bssid = wifi_net["bssid"]
            wifi_ssid = wifi_net["ssid"]
            wifi_timestamp = base_time - timedelta(
                seconds=random.randint(0, 1200)
            )  # Within 20 min
            wifi_signal_strength = random.uniform(-70, -30)  # dBm
        else:
            wifi_bssid = None
            wifi_ssid = None
            wifi_timestamp = None
            wifi_signal_strength = None

        # TLS fingerprint - consistent with device
        tls_config = random.choice(self.tls_configs)
        tls_fingerprint = self._generate_tls_fingerprint(device["browser_fp"])
        tls_timestamp = base_time - timedelta(
            seconds=random.randint(0, 900)
        )  # Within 15 min

        # Threat intelligence - clean for legitimate
        ip_is_vpn = random.random() < 0.05  # 5% use VPN
        ip_is_tor = False
        ip_is_malicious = False
        ip_reputation_score = random.uniform(0.8, 1.0)

        # SIEM alerts - minimal for legitimate users
        siem_alerts_high = 0
        siem_alerts_medium = (
            1 if random.random() < 0.1 else 0
        )  # 10% have 1 medium alert
        siem_alerts_low = random.choice([0, 0, 0, 1, 2])  # Occasional low alerts

        return AuthSession(
            session_id=session_id,
            timestamp=base_time,
            user_id=f"USER_{random.randint(1000, 9999)}",
            is_attack=False,
            attack_type=None,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            gps_timestamp=gps_timestamp,
            gps_accuracy=gps_accuracy,
            ip_address=ip_address,
            ip_lat=ip_lat,
            ip_lon=ip_lon,
            ip_timestamp=ip_timestamp,
            ip_country=region["name"],
            ip_asn=random.choice(self.legitimate_asns),
            device_id=device_id,
            device_os=device["os"],
            device_os_version=random.choice(device["versions"]),
            device_last_scan=device_last_scan,
            device_compliance_score=device_compliance_score,
            device_av_status=True,
            device_encryption=True,
            wifi_bssid=wifi_bssid,
            wifi_ssid=wifi_ssid,
            wifi_timestamp=wifi_timestamp,
            wifi_signal_strength=wifi_signal_strength,
            tls_fingerprint=tls_fingerprint,
            tls_timestamp=tls_timestamp,
            tls_cipher_suite=tls_config["cipher"],
            tls_version=tls_config["version"],
            ip_is_vpn=ip_is_vpn,
            ip_is_tor=ip_is_tor,
            ip_is_malicious=ip_is_malicious,
            ip_reputation_score=ip_reputation_score,
            siem_alerts_high=siem_alerts_high,
            siem_alerts_medium=siem_alerts_medium,
            siem_alerts_low=siem_alerts_low,
            true_location_lat=true_lat,
            true_location_lon=true_lon,
            legitimate_device=True,
        )

    def _generate_attack_session(
        self, session_id: str, attack_type: str
    ) -> AuthSession:
        """Generate an attack session based on attack type"""

        base_time = datetime.now() - timedelta(seconds=random.randint(0, 300))

        if attack_type == "geo_spoof":
            return self._generate_geo_spoof_attack(session_id, base_time)
        elif attack_type == "stale_data":
            return self._generate_stale_data_attack(session_id, base_time)
        elif attack_type == "device_compromise":
            return self._generate_device_compromise_attack(session_id, base_time)
        elif attack_type == "network_manipulation":
            return self._generate_network_manipulation_attack(session_id, base_time)
        else:
            raise ValueError(f"Unknown attack type: {attack_type}")

    def _generate_geo_spoof_attack(
        self, session_id: str, base_time: datetime
    ) -> AuthSession:
        """
        Geographic spoofing attack: Attacker in one location, spoofed GPS/IP elsewhere
        """
        # Attacker's true location (e.g., Russia, China, Eastern Europe)
        attacker_regions = [
            {"name": "Moscow", "lat": 55.7558, "lon": 37.6173},
            {"name": "Beijing", "lat": 39.9042, "lon": 116.4074},
            {"name": "Lagos", "lat": 6.5244, "lon": 3.3792},
        ]
        attacker_region = random.choice(attacker_regions)
        true_lat, true_lon = self._random_location_in_radius(
            attacker_region["lat"], attacker_region["lon"], 100
        )

        # Spoofed location (victim's region)
        victim_region = random.choice(self.legitimate_regions)
        spoofed_lat, spoofed_lon = self._random_location_in_radius(
            victim_region["lat"], victim_region["lon"], 20
        )

        # GPS appears to be from spoofed location, but may have inconsistencies
        gps_lat, gps_lon = spoofed_lat, spoofed_lon
        gps_timestamp = base_time - timedelta(seconds=random.randint(0, 200))
        gps_accuracy = random.uniform(5, 30)

        # IP reveals true location (harder to spoof consistently)
        ip_lat, ip_lon = self._add_location_noise(true_lat, true_lon, 0.1)
        ip_timestamp = base_time - timedelta(seconds=random.randint(0, 300))
        ip_address = self._generate_ip_address(attacker_region["name"])

        # Device may be legitimate (stolen credentials) or compromised
        device = random.choice(self.device_types)
        device_id = f"DEV_{random.randint(100000, 999999)}"
        device_last_scan = base_time - timedelta(hours=random.randint(2, 48))
        device_compliance_score = random.uniform(0.6, 0.9)

        # WiFi likely absent or inconsistent
        wifi_bssid = None
        wifi_ssid = None
        wifi_timestamp = None
        wifi_signal_strength = None

        # TLS fingerprint
        tls_config = random.choice(self.tls_configs)
        tls_fingerprint = self._generate_tls_fingerprint(device["browser_fp"])
        tls_timestamp = base_time - timedelta(seconds=random.randint(0, 600))

        # Threat intelligence - may show VPN/proxy usage
        ip_is_vpn = random.random() < 0.6  # 60% use VPN
        ip_is_tor = random.random() < 0.2  # 20% use TOR
        ip_is_malicious = random.random() < 0.15
        ip_reputation_score = random.uniform(0.3, 0.7)

        # SIEM alerts - potential suspicious activity
        siem_alerts_high = 1 if random.random() < 0.3 else 0
        siem_alerts_medium = random.choice([0, 1, 2])
        siem_alerts_low = random.choice([1, 2, 3])

        return AuthSession(
            session_id=session_id,
            timestamp=base_time,
            user_id=f"USER_{random.randint(1000, 9999)}",
            is_attack=True,
            attack_type="geo_spoof",
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            gps_timestamp=gps_timestamp,
            gps_accuracy=gps_accuracy,
            ip_address=ip_address,
            ip_lat=ip_lat,
            ip_lon=ip_lon,
            ip_timestamp=ip_timestamp,
            ip_country=attacker_region["name"],
            ip_asn=random.choice(self.vpn_asns if ip_is_vpn else self.legitimate_asns),
            device_id=device_id,
            device_os=device["os"],
            device_os_version=random.choice(device["versions"]),
            device_last_scan=device_last_scan,
            device_compliance_score=device_compliance_score,
            device_av_status=random.random() < 0.8,
            device_encryption=random.random() < 0.9,
            wifi_bssid=wifi_bssid,
            wifi_ssid=wifi_ssid,
            wifi_timestamp=wifi_timestamp,
            wifi_signal_strength=wifi_signal_strength,
            tls_fingerprint=tls_fingerprint,
            tls_timestamp=tls_timestamp,
            tls_cipher_suite=tls_config["cipher"],
            tls_version=tls_config["version"],
            ip_is_vpn=ip_is_vpn,
            ip_is_tor=ip_is_tor,
            ip_is_malicious=ip_is_malicious,
            ip_reputation_score=ip_reputation_score,
            siem_alerts_high=siem_alerts_high,
            siem_alerts_medium=siem_alerts_medium,
            siem_alerts_low=siem_alerts_low,
            true_location_lat=true_lat,
            true_location_lon=true_lon,
            legitimate_device=False,
        )

    def _generate_stale_data_attack(
        self, session_id: str, base_time: datetime
    ) -> AuthSession:
        """
        Stale data attack: Using cached/old authentication data (replay attack)
        """
        # Legitimate location
        region = random.choice(self.legitimate_regions)
        true_lat, true_lon = self._random_location_in_radius(
            region["lat"], region["lon"], 50
        )

        # Key indicator: OLD timestamps (outside freshness windows)
        stale_hours = random.uniform(24, 72)  # 1-3 days old

        gps_lat, gps_lon = self._add_location_noise(true_lat, true_lon, 0.02)
        gps_timestamp = base_time - timedelta(hours=stale_hours)  # STALE!
        gps_accuracy = random.uniform(10, 100)

        ip_lat, ip_lon = self._add_location_noise(true_lat, true_lon, 0.15)
        ip_timestamp = base_time - timedelta(hours=random.uniform(12, 48))  # STALE!
        ip_address = self._generate_ip_address(region["name"])

        # Device data also stale
        device = random.choice(self.device_types)
        device_id = f"DEV_{random.randint(100000, 999999)}"
        device_last_scan = base_time - timedelta(
            days=random.randint(30, 90)
        )  # Very stale!
        device_compliance_score = random.uniform(0.5, 0.8)

        # WiFi data stale or absent
        if random.random() < 0.4:
            wifi_net = random.choice(self.wifi_networks)
            wifi_bssid = wifi_net["bssid"]
            wifi_ssid = wifi_net["ssid"]
            wifi_timestamp = base_time - timedelta(
                hours=random.uniform(24, 96)
            )  # STALE!
            wifi_signal_strength = random.uniform(-80, -40)
        else:
            wifi_bssid = None
            wifi_ssid = None
            wifi_timestamp = None
            wifi_signal_strength = None

        # TLS data also stale
        tls_config = random.choice(self.tls_configs)
        tls_fingerprint = self._generate_tls_fingerprint(device["browser_fp"])
        tls_timestamp = base_time - timedelta(hours=random.uniform(12, 36))  # STALE!

        # Threat intelligence - may be clean (replaying legitimate data)
        ip_is_vpn = random.random() < 0.2
        ip_is_tor = False
        ip_is_malicious = random.random() < 0.1
        ip_reputation_score = random.uniform(0.6, 0.9)

        # SIEM alerts - may show unusual timing patterns
        siem_alerts_high = 0
        siem_alerts_medium = 1 if random.random() < 0.4 else 0
        siem_alerts_low = random.choice([1, 2, 3])

        return AuthSession(
            session_id=session_id,
            timestamp=base_time,
            user_id=f"USER_{random.randint(1000, 9999)}",
            is_attack=True,
            attack_type="stale_data",
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            gps_timestamp=gps_timestamp,
            gps_accuracy=gps_accuracy,
            ip_address=ip_address,
            ip_lat=ip_lat,
            ip_lon=ip_lon,
            ip_timestamp=ip_timestamp,
            ip_country=region["name"],
            ip_asn=random.choice(self.legitimate_asns),
            device_id=device_id,
            device_os=device["os"],
            device_os_version=random.choice(device["versions"]),
            device_last_scan=device_last_scan,
            device_compliance_score=device_compliance_score,
            device_av_status=random.random() < 0.7,
            device_encryption=random.random() < 0.85,
            wifi_bssid=wifi_bssid,
            wifi_ssid=wifi_ssid,
            wifi_timestamp=wifi_timestamp,
            wifi_signal_strength=wifi_signal_strength,
            tls_fingerprint=tls_fingerprint,
            tls_timestamp=tls_timestamp,
            tls_cipher_suite=tls_config["cipher"],
            tls_version=tls_config["version"],
            ip_is_vpn=ip_is_vpn,
            ip_is_tor=ip_is_tor,
            ip_is_malicious=ip_is_malicious,
            ip_reputation_score=ip_reputation_score,
            siem_alerts_high=siem_alerts_high,
            siem_alerts_medium=siem_alerts_medium,
            siem_alerts_low=siem_alerts_low,
            true_location_lat=true_lat,
            true_location_lon=true_lon,
            legitimate_device=False,
        )

    def _generate_device_compromise_attack(
        self, session_id: str, base_time: datetime
    ) -> AuthSession:
        """
        Device compromise attack: Legitimate device compromised with malware/poor posture
        """
        region = random.choice(self.legitimate_regions)
        true_lat, true_lon = self._random_location_in_radius(
            region["lat"], region["lon"], 50
        )

        # Location data looks legitimate
        gps_lat, gps_lon = self._add_location_noise(true_lat, true_lon, 0.01)
        gps_timestamp = base_time - timedelta(seconds=random.randint(0, 200))
        gps_accuracy = random.uniform(5, 40)

        ip_lat, ip_lon = self._add_location_noise(true_lat, true_lon, 0.1)
        ip_timestamp = base_time - timedelta(seconds=random.randint(0, 400))
        ip_address = self._generate_ip_address(region["name"])

        # Device shows POOR POSTURE (key indicator)
        device = random.choice(self.device_types)
        device_id = f"DEV_{random.randint(100000, 999999)}"
        device_last_scan = base_time - timedelta(
            days=random.randint(30, 120)
        )  # Not scanned recently
        device_compliance_score = random.uniform(0.2, 0.6)  # LOW SCORE!
        device_av_status = random.random() < 0.3  # Often disabled
        device_encryption = random.random() < 0.5  # Often not encrypted

        # WiFi may be present
        if random.random() < 0.6:
            wifi_net = random.choice(self.wifi_networks)
            wifi_bssid = wifi_net["bssid"]
            wifi_ssid = wifi_net["ssid"]
            wifi_timestamp = base_time - timedelta(seconds=random.randint(0, 1500))
            wifi_signal_strength = random.uniform(-75, -35)
        else:
            wifi_bssid = None
            wifi_ssid = None
            wifi_timestamp = None
            wifi_signal_strength = None

        # TLS fingerprint may be unusual (malware modifying traffic)
        tls_config = random.choice(self.tls_configs)
        tls_fingerprint = self._generate_tls_fingerprint(
            "compromised_" + device["browser_fp"]
        )
        tls_timestamp = base_time - timedelta(seconds=random.randint(0, 800))

        # Threat intelligence
        ip_is_vpn = random.random() < 0.1
        ip_is_tor = False
        ip_is_malicious = random.random() < 0.05
        ip_reputation_score = random.uniform(0.5, 0.85)

        # SIEM alerts - HIGH activity from compromised device
        siem_alerts_high = random.choice([1, 2, 3])  # HIGH ALERTS!
        siem_alerts_medium = random.choice([2, 3, 4])
        siem_alerts_low = random.choice([3, 5, 7])

        return AuthSession(
            session_id=session_id,
            timestamp=base_time,
            user_id=f"USER_{random.randint(1000, 9999)}",
            is_attack=True,
            attack_type="device_compromise",
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            gps_timestamp=gps_timestamp,
            gps_accuracy=gps_accuracy,
            ip_address=ip_address,
            ip_lat=ip_lat,
            ip_lon=ip_lon,
            ip_timestamp=ip_timestamp,
            ip_country=region["name"],
            ip_asn=random.choice(self.legitimate_asns),
            device_id=device_id,
            device_os=device["os"],
            device_os_version=random.choice(device["versions"]),
            device_last_scan=device_last_scan,
            device_compliance_score=device_compliance_score,
            device_av_status=device_av_status,
            device_encryption=device_encryption,
            wifi_bssid=wifi_bssid,
            wifi_ssid=wifi_ssid,
            wifi_timestamp=wifi_timestamp,
            wifi_signal_strength=wifi_signal_strength,
            tls_fingerprint=tls_fingerprint,
            tls_timestamp=tls_timestamp,
            tls_cipher_suite=tls_config["cipher"],
            tls_version=tls_config["version"],
            ip_is_vpn=ip_is_vpn,
            ip_is_tor=ip_is_tor,
            ip_is_malicious=ip_is_malicious,
            ip_reputation_score=ip_reputation_score,
            siem_alerts_high=siem_alerts_high,
            siem_alerts_medium=siem_alerts_medium,
            siem_alerts_low=siem_alerts_low,
            true_location_lat=true_lat,
            true_location_lon=true_lon,
            legitimate_device=False,
        )

    def _generate_network_manipulation_attack(
        self, session_id: str, base_time: datetime
    ) -> AuthSession:
        """
        Network manipulation attack: Using VPN/TOR/proxies from suspicious locations
        """
        # Attacker's true location (hidden)
        attacker_regions = [
            {"name": "Unknown VPN", "lat": 0, "lon": 0},
            {"name": "TOR Exit Node", "lat": 0, "lon": 0},
        ]
        attacker_region = random.choice(attacker_regions)

        # VPN/TOR endpoint location
        vpn_regions = random.choice(self.legitimate_regions)
        true_lat, true_lon = self._random_location_in_radius(
            vpn_regions["lat"], vpn_regions["lon"], 100
        )

        # Location data may be inconsistent or hidden
        gps_lat, gps_lon = self._add_location_noise(
            true_lat, true_lon, 0.5
        )  # Large error
        gps_timestamp = base_time - timedelta(seconds=random.randint(0, 400))
        gps_accuracy = random.uniform(50, 500)  # Poor accuracy

        ip_lat, ip_lon = self._add_location_noise(true_lat, true_lon, 0.3)
        ip_timestamp = base_time - timedelta(seconds=random.randint(0, 300))
        ip_address = self._generate_ip_address(vpn_regions["name"])

        # Device data
        device = random.choice(self.device_types)
        device_id = f"DEV_{random.randint(100000, 999999)}"
        device_last_scan = base_time - timedelta(hours=random.randint(2, 72))
        device_compliance_score = random.uniform(0.4, 0.85)

        # WiFi likely absent (using VPN/TOR)
        wifi_bssid = None
        wifi_ssid = None
        wifi_timestamp = None
        wifi_signal_strength = None

        # TLS fingerprint
        tls_config = random.choice(self.tls_configs)
        tls_fingerprint = self._generate_tls_fingerprint(device["browser_fp"])
        tls_timestamp = base_time - timedelta(seconds=random.randint(0, 600))

        # Threat intelligence - KEY INDICATORS!
        ip_is_vpn = random.random() < 0.8  # 80% flagged as VPN
        ip_is_tor = random.random() < 0.4  # 40% flagged as TOR
        ip_is_malicious = random.random() < 0.25  # 25% known malicious
        ip_reputation_score = random.uniform(0.1, 0.5)  # LOW REPUTATION!

        # SIEM alerts - suspicious network activity
        siem_alerts_high = 1 if random.random() < 0.4 else 0
        siem_alerts_medium = random.choice([1, 2, 3])
        siem_alerts_low = random.choice([2, 3, 4])

        return AuthSession(
            session_id=session_id,
            timestamp=base_time,
            user_id=f"USER_{random.randint(1000, 9999)}",
            is_attack=True,
            attack_type="network_manipulation",
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            gps_timestamp=gps_timestamp,
            gps_accuracy=gps_accuracy,
            ip_address=ip_address,
            ip_lat=ip_lat,
            ip_lon=ip_lon,
            ip_timestamp=ip_timestamp,
            ip_country=vpn_regions["name"],
            ip_asn=random.choice(self.vpn_asns if ip_is_vpn else self.malicious_asns),
            device_id=device_id,
            device_os=device["os"],
            device_os_version=random.choice(device["versions"]),
            device_last_scan=device_last_scan,
            device_compliance_score=device_compliance_score,
            device_av_status=random.random() < 0.7,
            device_encryption=random.random() < 0.85,
            wifi_bssid=wifi_bssid,
            wifi_ssid=wifi_ssid,
            wifi_timestamp=wifi_timestamp,
            wifi_signal_strength=wifi_signal_strength,
            tls_fingerprint=tls_fingerprint,
            tls_timestamp=tls_timestamp,
            tls_cipher_suite=tls_config["cipher"],
            tls_version=tls_config["version"],
            ip_is_vpn=ip_is_vpn,
            ip_is_tor=ip_is_tor,
            ip_is_malicious=ip_is_malicious,
            ip_reputation_score=ip_reputation_score,
            siem_alerts_high=siem_alerts_high,
            siem_alerts_medium=siem_alerts_medium,
            siem_alerts_low=siem_alerts_low,
            true_location_lat=true_lat,
            true_location_lon=true_lon,
            legitimate_device=False,
        )

    # Helper methods
    def _random_location_in_radius(
        self, center_lat: float, center_lon: float, radius_km: float
    ) -> Tuple[float, float]:
        """Generate a random location within a radius of a center point"""
        # Convert radius to degrees (approximate)
        radius_deg = radius_km / 111.0  # 1 degree ≈ 111 km

        # Random angle and distance
        angle = random.uniform(0, 2 * np.pi)
        distance = random.uniform(0, radius_deg)

        # Calculate new position
        lat = center_lat + distance * np.cos(angle)
        lon = center_lon + distance * np.sin(angle)

        return lat, lon

    def _add_location_noise(
        self, lat: float, lon: float, noise_deg: float
    ) -> Tuple[float, float]:
        """Add random noise to a location"""
        noise_lat = random.gauss(0, noise_deg)
        noise_lon = random.gauss(0, noise_deg)
        return lat + noise_lat, lon + noise_lon

    def _generate_ip_address(self, region_name: str) -> str:
        """Generate a realistic IP address for a region"""
        # Simple IP generation based on region
        region_prefixes = {
            "New York": "192.168",
            "London": "10.0",
            "Tokyo": "172.16",
            "San Francisco": "192.168",
            "Berlin": "10.1",
            "Singapore": "172.17",
            "Sydney": "192.169",
            "Toronto": "10.2",
            "Moscow": "185.220",
            "Beijing": "202.108",
            "Lagos": "41.203",
            "Unknown VPN": "198.51",
            "TOR Exit Node": "185.220",
        }

        prefix = region_prefixes.get(region_name, "192.168")
        third_octet = random.randint(0, 255)
        fourth_octet = random.randint(1, 254)
        return f"{prefix}.{third_octet}.{fourth_octet}"

    def _generate_tls_fingerprint(self, browser_type: str) -> str:
        """Generate a TLS fingerprint based on browser type"""
        # Simplified JA3 fingerprint generation
        fingerprints = {
            "win_chrome": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
            "mac_safari": "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,65281-0-23-13-5-18-16-30032-11-10-27-21,29-23-24-25,0",
            "linux_firefox": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24,0",
            "ios_safari": "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47,65281-0-23-13-5-18-16-11-10-27-21,29-23-24-25,0",
            "android_chrome": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-27-21,29-23-24,0",
        }

        # For compromised devices, modify the fingerprint slightly
        if "compromised" in browser_type:
            browser_type = browser_type.replace("compromised_", "")
            fp = fingerprints.get(browser_type, fingerprints["win_chrome"])
            # Modify slightly to indicate anomaly
            fp = fp.replace("771", "769")
            return fp

        return fingerprints.get(browser_type, fingerprints["win_chrome"])

    def _sessions_to_dataframe(self, sessions: List[AuthSession]) -> pd.DataFrame:
        """Convert list of AuthSession objects to pandas DataFrame"""
        data = []
        for session in sessions:
            data.append(
                {
                    "session_id": session.session_id,
                    "timestamp": session.timestamp,
                    "user_id": session.user_id,
                    "is_attack": session.is_attack,
                    "attack_type": session.attack_type,
                    "gps_lat": session.gps_lat,
                    "gps_lon": session.gps_lon,
                    "gps_timestamp": session.gps_timestamp,
                    "gps_accuracy": session.gps_accuracy,
                    "ip_address": session.ip_address,
                    "ip_lat": session.ip_lat,
                    "ip_lon": session.ip_lon,
                    "ip_timestamp": session.ip_timestamp,
                    "ip_country": session.ip_country,
                    "ip_asn": session.ip_asn,
                    "device_id": session.device_id,
                    "device_os": session.device_os,
                    "device_os_version": session.device_os_version,
                    "device_last_scan": session.device_last_scan,
                    "device_compliance_score": session.device_compliance_score,
                    "device_av_status": session.device_av_status,
                    "device_encryption": session.device_encryption,
                    "wifi_bssid": session.wifi_bssid,
                    "wifi_ssid": session.wifi_ssid,
                    "wifi_timestamp": session.wifi_timestamp,
                    "wifi_signal_strength": session.wifi_signal_strength,
                    "tls_fingerprint": session.tls_fingerprint,
                    "tls_timestamp": session.tls_timestamp,
                    "tls_cipher_suite": session.tls_cipher_suite,
                    "tls_version": session.tls_version,
                    "ip_is_vpn": session.ip_is_vpn,
                    "ip_is_tor": session.ip_is_tor,
                    "ip_is_malicious": session.ip_is_malicious,
                    "ip_reputation_score": session.ip_reputation_score,
                    "siem_alerts_high": session.siem_alerts_high,
                    "siem_alerts_medium": session.siem_alerts_medium,
                    "siem_alerts_low": session.siem_alerts_low,
                    "true_location_lat": session.true_location_lat,
                    "true_location_lon": session.true_location_lon,
                    "legitimate_device": session.legitimate_device,
                }
            )

        return pd.DataFrame(data)


# Example usage
if __name__ == "__main__":
    print("=" * 70)
    print("Zero Trust MFA Dataset Generator")
    print("=" * 70)

    # Create generator
    generator = DatasetGenerator(seed=42)

    # Generate dataset
    df = generator.generate_dataset(
        n_sessions=5000,
        attack_ratio=0.20,
        attack_distribution={
            "geo_spoof": 0.40,
            "stale_data": 0.30,
            "device_compromise": 0.20,
            "network_manipulation": 0.10,
        },
    )

    # Save to CSV
    output_file = "../data/synthetic_auth_sessions.csv"
    df.to_csv(output_file, index=False)
    print(f"\nDataset saved to: {output_file}")

    # Display sample statistics
    print("\n" + "=" * 70)
    print("Dataset Statistics")
    print("=" * 70)
    print(f"\nTotal sessions: {len(df)}")
    print(f"Features: {len(df.columns)}")
    print(f"\nClass distribution:")
    print(df["is_attack"].value_counts())
    print(f"\nAttack types:")
    print(df[df["is_attack"]]["attack_type"].value_counts())
