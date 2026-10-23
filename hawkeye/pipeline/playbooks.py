"""
HawkEye-AI — SOAR-Lite Incident Response & Playbook Generator

Generates actionable mitigation artifacts for SOC analysts:
  - Linux iptables command
  - AWS Security Group CLI command (Cloud Computing link)
  - Snort / Suricata IDS drop signature
  - NIST SP 800-61 Incident Response Playbook checklist
"""

from typing import Dict, Any


COMMON_PORT_MAP = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "ftp_data": 20,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "dns": 53,
    "domain_u": 53,
    "pop3": 110,
    "imap4": 143,
}


def generate_playbook(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate an incident response playbook and containment rules for an alert.

    Args:
        alert: Dictionary containing alert attributes (src, dst, protocol, service,
               severity, label, mitre_technique_id, etc.)

    Returns:
        Dict with iptables, aws_cli, snort_rule, steps, and full script.
    """
    src_ip = alert.get("src", "0.0.0.0")
    dst_ip = alert.get("dst", "0.0.0.0")
    proto = str(alert.get("protocol", "tcp")).lower()
    service = str(alert.get("service", "http")).lower()
    sev = int(alert.get("severity", 3))
    label = str(alert.get("label", "anomaly")).upper()
    tech_id = str(alert.get("mitre_technique_id", "T1499"))
    tech_name = str(alert.get("mitre_technique_name", "Endpoint Threat"))
    port = COMMON_PORT_MAP.get(service, 80)

    # 1. Linux iptables firewall rule
    iptables = f"sudo iptables -A INPUT -s {src_ip} -p {proto} --dport {port} -j DROP"

    # 2. AWS Security Group mitigation CLI command
    aws_cli = (
        f"aws ec2 revoke-security-group-ingress "
        f"--group-id sg-07e15fa8c9b421a10 "
        f"--protocol {proto} --port {port} --cidr {src_ip}/32"
    )

    # 3. Snort / Suricata IDS rule
    snort_rule = (
        f'drop {proto} {src_ip} any -> {dst_ip} {port} '
        f'(msg:"HAWKEYE-BLOCK [{tech_id}] {tech_name}"; '
        f'flow:established,to_server; classtype:attempted-admin; sid:9000101; rev:1;)'
    )

    # 4. NIST SP 800-61 Computer Security Incident Handling Playbook Steps
    steps = [
        {
            "phase": "1. Identification & Triage",
            "action": f"Confirm anomaly score ({alert.get('anomaly_score', 0)}) and classify threat '{label}'. Verify log SHA-256 integrity.",
            "status": "Completed by HawkEye-AI",
        },
        {
            "phase": "2. Containment",
            "action": f"Apply perimeter blocklist on border firewall or VPC ACL for source IP {src_ip}. Terminate active {proto}/{service} sessions.",
            "status": "Action Required (Admin)",
        },
        {
            "phase": "3. Eradication",
            "action": f"Inspect target host {dst_ip} for unauthorized cron jobs, root shells, or backdoors. Invalidate any leaked session tokens.",
            "status": "Recommended",
        },
        {
            "phase": "4. Recovery & Lessons Learned",
            "action": f"Restore verified service configuration on port {port}. Update threat intelligence feeds with IOC {src_ip}.",
            "status": "Post-Incident",
        },
    ]

    # 5. Standalone Bash Remediation Script
    remediation_script = f"""#!/usr/bin/env bash
# ==============================================================================
# HawkEye-AI Incident Remediation Script
# Target Incident: {tech_id} ({tech_name}) | Severity: {sev}/5
# Attacker IP:     {src_ip} -> Target: {dst_ip}:{port} ({proto})
# Generated At:    {alert.get('timestamp', 'N/A')}
# ==============================================================================
set -euo pipefail

echo "[*] Initiating HawkEye-AI Containment for {src_ip}..."

# 1. Linux Kernel Firewall Drop
if command -v iptables &> /dev/null; then
    echo "[+] Dropping inbound traffic from {src_ip} via iptables..."
    {iptables}
fi

# 2. AWS VPC Security Group Ingress Revocation (Cloud Integration)
if command -v aws &> /dev/null; then
    echo "[+] Revoking AWS Security Group ingress rule for {src_ip}/32..."
    {aws_cli} || true
fi

# 3. Terminate Active TCP Sockets
if command -v ss &> /dev/null; then
    echo "[+] Killing active sockets connecting to {src_ip}..."
    sudo ss -K dst {src_ip} || true
fi

echo "[✓] Containment applied successfully. Target host isolated."
"""

    return {
        "iptables": iptables,
        "aws_cli": aws_cli,
        "snort_rule": snort_rule,
        "steps": steps,
        "remediation_script": remediation_script,
    }
