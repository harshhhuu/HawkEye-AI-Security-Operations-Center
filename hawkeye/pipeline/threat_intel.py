"""
HawkEye-AI — Threat Intelligence & MITRE ATT&CK / CIA Triad Mapping

Maps detected network anomalies and security events to:
  1. The CIA Triad (Confidentiality, Integrity, Availability)
  2. The MITRE ATT&CK Enterprise Matrix (Tactics and Techniques)
"""

from typing import Dict, Any


# ---------------------------------------------------------------------------
# MITRE ATT&CK Technique Definitions
# ---------------------------------------------------------------------------
MITRE_TECHNIQUES = {
    "dos": {
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "cia_primary": "Availability",
        "description": "Adversary attacks availability of systems through resource exhaustion.",
    },
    "fuzzers": {
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique_id": "T1499.004",
        "technique_name": "Application or System Exploitation",
        "cia_primary": "Availability",
        "description": "Sending randomized, malformed packets to crash application services.",
    },
    "probe": {
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "cia_primary": "Confidentiality",
        "description": "Port scanning and service enumeration to discover exploitable vectors.",
    },
    "reconnaissance": {
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "cia_primary": "Confidentiality",
        "description": "Pre-attack network scanning and banner grabbing against edge services.",
    },
    "exploits": {
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "cia_primary": "Confidentiality",
        "description": "Leveraging software bugs to execute arbitrary payloads or breach access.",
    },
    "backdoor": {
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts & Backdoors",
        "cia_primary": "Integrity",
        "description": "Unattended remote access channel maintained to bypass authentication.",
    },
    "shellcode": {
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "cia_primary": "Integrity",
        "description": "Injecting native assembly instructions directly into memory to spawn root shells.",
    },
    "worms": {
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services",
        "cia_primary": "Availability",
        "description": "Self-replicating malicious payloads traversing internal subnets.",
    },
    "generic": {
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique_id": "T1027",
        "technique_name": "Obfuscated / Anomalous Traffic",
        "cia_primary": "Integrity",
        "description": "Unusual protocol flag combinations attempting to bypass perimeter IDS.",
    },
    "r2l": {
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique_id": "T1110",
        "technique_name": "Brute Force / Remote Unauthorized Access",
        "cia_primary": "Confidentiality",
        "description": "Unauthorized remote user attempting credential theft or access violation.",
    },
    "u2r": {
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "cia_primary": "Integrity",
        "description": "Local non-privileged user attempting root/administrator privilege elevation.",
    },
    "normal": {
        "tactic": "Normal Operations",
        "tactic_id": "N/A",
        "technique_id": "N/A",
        "technique_name": "Legitimate Traffic",
        "cia_primary": "None",
        "description": "Baseline non-malicious network activity.",
    },
}

# Heuristics for when label is missing or generic anomaly
FALLBACK_SERVICE_MAP = {
    "http": ("T1190", "Exploit Public-Facing Application", "Initial Access", "Confidentiality"),
    "ftp": ("T1110", "Brute Force", "Credential Access", "Confidentiality"),
    "ssh": ("T1021.004", "Remote Services: SSH", "Lateral Movement", "Confidentiality"),
    "telnet": ("T1021", "Remote Services", "Lateral Movement", "Confidentiality"),
    "smtp": ("T1566", "Phishing / Mail Exploitation", "Initial Access", "Confidentiality"),
    "dns": ("T1071.004", "Application Layer Protocol: DNS", "Command and Control", "Availability"),
    "domain_u": ("T1071.004", "Application Layer Protocol: DNS", "Command and Control", "Availability"),
}


def map_mitre_and_cia(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a log row or alert dict with MITRE ATT&CK technique and CIA triad impact.

    Args:
        row: Dictionary or Series with keys like 'label', 'service', 'bytes_sent', etc.

    Returns:
        Dict with keys:
          - cia_impact: 'Confidentiality' | 'Integrity' | 'Availability' | 'None'
          - mitre_tactic: e.g. 'Impact', 'Discovery'
          - mitre_tactic_id: e.g. 'TA0040'
          - mitre_technique_id: e.g. 'T1499'
          - mitre_technique_name: e.g. 'Endpoint Denial of Service'
          - mitre_url: clickable link to MITRE ATT&CK portal
    """
    label = str(row.get("label", "")).lower().strip()
    service = str(row.get("service_original", row.get("service", ""))).lower().strip()
    bytes_sent = int(row.get("bytes_sent", row.get("src_bytes", 0)) or 0)
    bytes_recv = int(row.get("bytes_recv", row.get("dst_bytes", 0)) or 0)
    failed_logins = int(row.get("num_failed_logins", 0) or 0)
    root_shell = int(row.get("root_shell", 0) or 0)

    # 1. Check direct attack category mapping (excluding normal)
    if label in MITRE_TECHNIQUES and label != "normal":
        tech = MITRE_TECHNIQUES[label]
        tactic = tech["tactic"]
        tactic_id = tech["tactic_id"]
        technique_id = tech["technique_id"]
        technique_name = tech["technique_name"]
        cia_impact = tech["cia_primary"]
    elif root_shell > 0:
        tech = MITRE_TECHNIQUES["u2r"]
        tactic = tech["tactic"]
        tactic_id = tech["tactic_id"]
        technique_id = tech["technique_id"]
        technique_name = tech["technique_name"]
        cia_impact = tech["cia_primary"]
    elif failed_logins >= 2:
        tech = MITRE_TECHNIQUES["r2l"]
        tactic = tech["tactic"]
        tactic_id = tech["tactic_id"]
        technique_id = tech["technique_id"]
        technique_name = tech["technique_name"]
        cia_impact = tech["cia_primary"]
    elif bytes_sent > 50000 and bytes_recv == 0:
        # High volume asymmetric out -> DoS
        tech = MITRE_TECHNIQUES["dos"]
        tactic = tech["tactic"]
        tactic_id = tech["tactic_id"]
        technique_id = tech["technique_id"]
        technique_name = tech["technique_name"]
        cia_impact = "Availability"
    elif service in FALLBACK_SERVICE_MAP:
        tid, tname, tac, cia = FALLBACK_SERVICE_MAP[service]
        technique_id = tid
        technique_name = tname
        tactic = tac
        tactic_id = "TA0001"
        cia_impact = cia
    else:
        # Default fallback for anomalous behavior
        tech = MITRE_TECHNIQUES["generic"]
        tactic = tech["tactic"]
        tactic_id = tech["tactic_id"]
        technique_id = tech["technique_id"]
        technique_name = tech["technique_name"]
        cia_impact = "Integrity"

    mitre_url = (
        f"https://attack.mitre.org/techniques/{technique_id.split('.')[0]}/"
        if technique_id != "N/A"
        else "https://attack.mitre.org/"
    )

    return {
        "cia_impact": cia_impact,
        "mitre_tactic": tactic,
        "mitre_tactic_id": tactic_id,
        "mitre_technique_id": technique_id,
        "mitre_technique_name": technique_name,
        "mitre_url": mitre_url,
    }
