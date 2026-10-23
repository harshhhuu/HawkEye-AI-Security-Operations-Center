"""
HawkEye-AI — GeoIP Threat Intelligence & Mapping Module

Enriches network log IP addresses with geographic coordinates, ASN details,
and threat reputation scores for 3D/2D visual mapping.
"""

import hashlib
from typing import Dict, Any, List

# Realistic global SOC monitoring coordinates for external attackers
GLOBAL_LOCATIONS = [
    {"country": "United States", "city": "Ashburn", "lat": 39.0438, "lon": -77.4874, "asn": "AS14618 Amazon.com"},
    {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "asn": "AS24940 Hetzner Online"},
    {"country": "United Kingdom", "city": "London", "lat": 51.5074, "lon": -0.1278, "asn": "AS20712 Andrews & Arnold"},
    {"country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "asn": "AS1103 SURF B.V."},
    {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "asn": "AS12389 Rostelecom"},
    {"country": "China", "city": "Shenzhen", "lat": 22.5431, "lon": 114.0579, "asn": "AS4134 Chinanet"},
    {"country": "Japan", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503, "asn": "AS2516 KDDI Corp"},
    {"country": "Brazil", "city": "Sao Paulo", "lat": -23.5505, "lon": -46.6333, "asn": "AS28573 Claro Brasil"},
    {"country": "Australia", "city": "Sydney", "lat": -33.8688, "lon": 151.2093, "asn": "AS13335 Cloudflare Australia"},
    {"country": "India", "city": "Bengaluru", "lat": 12.9716, "lon": 77.5946, "asn": "AS55836 Reliance Jio"},
    {"country": "Singapore", "city": "Singapore", "lat": 1.3521, "lon": 103.8198, "asn": "AS4657 StarHub"},
    {"country": "France", "city": "Paris", "lat": 48.8566, "lon": 2.3522, "asn": "AS16276 OVH SAS"},
]

# Protected Cloud Perimeter (Target SOC Datacenter — e.g. AWS Cloud VPC)
TARGET_CLOUD_DATACENTER = {
    "name": "HawkEye Cloud VPC (AWS ap-south-1 Mumbai)",
    "city": "Mumbai",
    "country": "India",
    "lat": 19.0760,
    "lon": 72.8777,
}


def enrich_ip_geo(ip: str) -> Dict[str, Any]:
    """
    Deterministically map an IP address to realistic geographic coordinates.

    Uses a fast hash of the IP string so repeated runs for the same IP
    always point to the exact same country, city, and coordinates.
    """
    if not ip or ip in ("0.0.0.0", "localhost", "127.0.0.1"):
        loc = GLOBAL_LOCATIONS[0]
        return {
            "country": loc["country"],
            "city": loc["city"],
            "lat": loc["lat"],
            "lon": loc["lon"],
            "asn": loc["asn"],
        }

    # Deterministic index based on MD5 hash of IP
    h = int(hashlib.md5(ip.encode("utf-8")).hexdigest()[:8], 16)
    loc = GLOBAL_LOCATIONS[h % len(GLOBAL_LOCATIONS)]

    # Add a slight jitter so multiple IPs in the same city don't completely overlap
    jitter_lat = ((h % 100) - 50) * 0.015
    jitter_lon = (((h >> 8) % 100) - 50) * 0.015

    return {
        "country": loc["country"],
        "city": loc["city"],
        "lat": round(loc["lat"] + jitter_lat, 4),
        "lon": round(loc["lon"] + jitter_lon, 4),
        "asn": loc["asn"],
    }


def enrich_alert_geo(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich an alert dictionary with source and destination geographic details.
    """
    src_geo = enrich_ip_geo(alert.get("src", ""))
    dst_geo = enrich_ip_geo(alert.get("dst", ""))

    sev = int(alert.get("severity", 3))
    # Simulated IP abuse reputation score (0-100%) correlated with severity
    abuse_score = min(99, 35 + sev * 12 + (int(hashlib.md5(str(alert.get("src")).encode()).hexdigest()[:4], 16) % 15))

    return {
        "src_country": src_geo["country"],
        "src_city": src_geo["city"],
        "src_lat": src_geo["lat"],
        "src_lon": src_geo["lon"],
        "src_asn": src_geo["asn"],
        "dst_lat": TARGET_CLOUD_DATACENTER["lat"],
        "dst_lon": TARGET_CLOUD_DATACENTER["lon"],
        "dst_location": TARGET_CLOUD_DATACENTER["name"],
        "threat_reputation_score": abuse_score,
    }
