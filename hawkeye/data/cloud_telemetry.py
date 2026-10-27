"""
HawkEye-AI — AWS Cloud Telemetry & Flow Log Generator / Parser

Provides native ingestion and synthetic simulation of:
  1. AWS VPC Flow Logs (Standard Version 2 format)
  2. AWS CloudTrail & Management Plane events
  3. Cloud-native attack scenarios:
     - Cloud Port Scan & Security Group enumeration
     - S3 Bucket Data Exfiltration
     - EC2 Cloud Cryptomining / Resource Hijacking
     - Security Group Ingress Permissive Tampering
     - IAM Privilege Escalation & Credential Abuse
"""

import os
import random
from datetime import datetime, timedelta
import pandas as pd


# Standard AWS protocol number mapping
AWS_PROTOCOL_MAP = {
    6: "tcp",
    17: "udp",
    1: "icmp",
}

# Standard port to service mapping
PORT_SERVICE_MAP = {
    80: "http",
    443: "https",
    22: "ssh",
    21: "ftp",
    23: "telnet",
    25: "smtp",
    53: "dns",
    3389: "rdp",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
    3333: "cryptomining",
    4444: "cryptomining",
    8080: "http_proxy",
}

AWS_REGIONS = ["us-east-1", "ap-south-1", "eu-west-1", "us-west-2"]
AWS_VPCS = ["vpc-07e15fa8c9b421a10", "vpc-01a2b3c4d5e6f7089", "vpc-0987654321fedcba0"]
AWS_INSTANCES = ["i-0a87612f0b9e812d4", "i-0f987213bc45a6789", "i-03487123ef6789abc"]
AWS_IAM_USERS = [
    "arn:aws:iam::123456789012:user/admin-jdoe",
    "arn:aws:iam::123456789012:role/ec2-s3-access-role",
    "arn:aws:iam::123456789012:user/developer-temp",
    "arn:aws:iam::123456789012:user/contractor-ext",
]


def generate_aws_cloud_dataset(n: int = 500, seed: int = 42) -> pd.DataFrame:
    """
    Generate realistic AWS VPC Flow & CloudTrail telemetry logs
    including both legitimate cloud microservice operations and 
    cloud-specific intrusion attacks.

    Args:
        n:    Number of log entries to generate.
        seed: Random seed for reproducibility.

    Returns:
        Standardized pd.DataFrame ready for the HawkEye pipeline.
    """
    random.seed(seed)
    base_time = datetime(2026, 9, 1, 10, 0, 0)
    records = []

    # Distribution: ~70% normal cloud traffic, ~30% cloud attacks
    attack_types = [
        "cloud_port_scan",
        "cloud_storage_exfil",
        "cloud_cryptomining",
        "cloud_security_group_tamper",
        "iam_privilege_escalation",
    ]

    for i in range(n):
        timestamp = (base_time + timedelta(seconds=i * random.randint(2, 15))).isoformat()
        is_attack = random.random() < 0.30
        region = random.choice(AWS_REGIONS)
        vpc_id = random.choice(AWS_VPCS)
        instance_id = random.choice(AWS_INSTANCES)
        account_id = "123456789012"

        if not is_attack:
            # Normal cloud operations (HTTPS, internal DB queries, DNS)
            proto_num = random.choice([6, 17])
            proto_type = AWS_PROTOCOL_MAP.get(proto_num, "tcp")
            dst_port = random.choice([443, 80, 53, 3306, 5432, 6379])
            src_port = random.randint(32768, 61000)
            service = PORT_SERVICE_MAP.get(dst_port, "other")
            src_ip = f"10.0.{random.randint(1, 20)}.{random.randint(2, 250)}"
            dst_ip = f"10.0.{random.randint(1, 20)}.{random.randint(2, 250)}" if dst_port in (3306, 5432, 6379) else f"52.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            
            packets = random.randint(10, 250)
            bytes_sent = packets * random.randint(64, 1400)
            bytes_recv = packets * random.randint(64, 1400)
            action = "ACCEPT"
            flag = "SF"
            label = "normal"
            duration = random.randint(1, 15)
            iam_user = random.choice(AWS_IAM_USERS[:2])

        else:
            # Cloud attack scenarios
            scenario = random.choice(attack_types)
            iam_user = random.choice(AWS_IAM_USERS)

            if scenario == "cloud_port_scan":
                # External attacker scanning cloud VPC ingress ports
                proto_type = "tcp"
                src_ip = f"185.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                dst_ip = f"10.0.1.{random.randint(2, 50)}"
                src_port = random.randint(40000, 60000)
                dst_port = random.choice([22, 23, 3389, 8080, 21, 1433, 27017])
                service = PORT_SERVICE_MAP.get(dst_port, "other")
                packets = random.randint(1, 4)
                bytes_sent = packets * 44
                bytes_recv = 0
                action = "REJECT"  # Blocked by AWS Security Group
                flag = "REJ"
                label = "cloud_port_scan"
                duration = 0

            elif scenario == "cloud_storage_exfil":
                # Compromised EC2 instance dumping S3 data outbound to unauthorized IP
                proto_type = "tcp"
                src_ip = f"10.0.1.{random.randint(2, 50)}"
                dst_ip = f"198.51.100.{random.randint(1, 254)}"
                src_port = random.randint(40000, 60000)
                dst_port = 443
                service = "https"
                packets = random.randint(1500, 8000)
                bytes_sent = packets * random.randint(1200, 1500)  # Huge egress transfer
                bytes_recv = random.randint(500, 2000)
                action = "ACCEPT"
                flag = "SF"
                label = "cloud_storage_exfil"
                duration = random.randint(40, 300)

            elif scenario == "cloud_cryptomining":
                # EC2 instance hijacked to mine cryptocurrency via mining pool
                proto_type = "tcp"
                src_ip = f"10.0.2.{random.randint(2, 50)}"
                dst_ip = f"142.250.{random.randint(1, 254)}.{random.randint(1, 254)}"
                src_port = random.randint(35000, 55000)
                dst_port = random.choice([3333, 4444])
                service = "cryptomining"
                packets = random.randint(2000, 6000)
                bytes_sent = packets * 180
                bytes_recv = packets * 220
                action = "ACCEPT"
                flag = "SF"
                label = "cloud_cryptomining"
                duration = random.randint(100, 600)

            elif scenario == "cloud_security_group_tamper":
                # Security group opened 0.0.0.0/0 on port 22/3389 with brute force
                proto_type = "tcp"
                src_ip = f"103.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                dst_ip = f"10.0.1.{random.randint(2, 50)}"
                src_port = random.randint(45000, 65000)
                dst_port = random.choice([22, 3389])
                service = PORT_SERVICE_MAP.get(dst_port, "ssh")
                packets = random.randint(80, 400)
                bytes_sent = packets * 110
                bytes_recv = packets * 90
                action = "ACCEPT"
                flag = "S0"
                label = "cloud_security_group_tamper"
                duration = random.randint(15, 90)

            elif scenario == "iam_privilege_escalation":
                # Unauthorized API calls and privilege escalation attempt
                proto_type = "tcp"
                src_ip = f"194.26.{random.randint(1, 254)}.{random.randint(1, 254)}"
                dst_ip = f"10.0.0.1"
                src_port = random.randint(50000, 60000)
                dst_port = 443
                service = "https"
                packets = random.randint(30, 150)
                bytes_sent = packets * 250
                bytes_recv = packets * 450
                action = "REJECT"
                flag = "RSTO"
                label = "iam_privilege_escalation"
                duration = random.randint(5, 30)

        records.append({
            "timestamp": timestamp,
            "src": src_ip,
            "dst": dst_ip,
            "protocol_type": proto_type,
            "service": service,
            "flag": flag,
            "bytes_sent": bytes_sent,
            "bytes_recv": bytes_recv,
            "packets": packets,
            "src_port": src_port,
            "dst_port": dst_port,
            "duration": duration,
            "action": action,
            "cloud_provider": "AWS",
            "account_id": account_id,
            "aws_region": region,
            "vpc_id": vpc_id,
            "instance_id": instance_id,
            "iam_user": iam_user,
            "label": label,
        })

    df = pd.DataFrame(records)
    return df


def load_aws_vpc_flow_logs(path: str, sample_size: int = None) -> pd.DataFrame:
    """
    Parse native AWS VPC Flow Logs (Standard space-separated format):
    version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status

    Args:
        path: Path to VPC Flow Log file (.log, .txt, or .csv).
        sample_size: Optional row limit.

    Returns:
        Standardized DataFrame ready for HawkEye pipeline.
    """
    # Check if file has header or is space-separated
    try:
        # First try space-delimited standard VPC format
        df = pd.read_csv(
            path,
            sep=r"\s+",
            header=None,
            names=[
                "version", "account_id", "interface_id",
                "src", "dst", "src_port", "dst_port",
                "protocol", "packets", "bytes",
                "start", "end", "action", "log_status"
            ],
            on_bad_lines="skip",
        )
    except Exception:
        df = pd.read_csv(path)

    # Convert numeric protocol to name
    if "protocol" in df.columns:
        df["protocol_type"] = df["protocol"].map(lambda p: AWS_PROTOCOL_MAP.get(int(p) if str(p).isdigit() else p, "tcp"))
    else:
        df["protocol_type"] = "tcp"

    # Map destination port to known cloud services
    if "dst_port" in df.columns:
        df["service"] = df["dst_port"].map(lambda p: PORT_SERVICE_MAP.get(int(p) if str(p).isdigit() else 80, "other"))
    else:
        df["service"] = "other"

    # Bytes and duration
    if "bytes" in df.columns:
        df["bytes_sent"] = pd.to_numeric(df["bytes"], errors="coerce").fillna(0)
        df["bytes_recv"] = (df["bytes_sent"] * 0.4).astype(int)
    else:
        df["bytes_sent"] = 1000
        df["bytes_recv"] = 500

    if "start" in df.columns and "end" in df.columns:
        df["duration"] = pd.to_numeric(df["end"], errors="coerce").fillna(0) - pd.to_numeric(df["start"], errors="coerce").fillna(0)
        df["duration"] = df["duration"].clip(lower=0)
    else:
        df["duration"] = 1

    if "action" in df.columns:
        df["flag"] = df["action"].map(lambda a: "SF" if str(a).upper() == "ACCEPT" else "REJ")
    else:
        df["flag"] = "SF"

    # Timestamp
    if "start" in df.columns:
        df["timestamp"] = pd.to_datetime(pd.to_numeric(df["start"], errors="coerce"), unit="s", errors="coerce").dt.isoformat()
    else:
        df["timestamp"] = datetime.now().isoformat()

    # Cloud metadata defaults
    df["cloud_provider"] = "AWS"
    if "aws_region" not in df.columns:
        df["aws_region"] = "us-east-1"
    if "vpc_id" not in df.columns:
        df["vpc_id"] = "vpc-07e15fa8c9b421a10"
    if "instance_id" not in df.columns:
        df["instance_id"] = "i-0a87612f0b9e812d4"

    # Heuristic label if not present
    if "label" not in df.columns:
        labels = []
        for _, row in df.iterrows():
            act = str(row.get("action", "ACCEPT")).upper()
            port = int(row.get("dst_port", 80)) if str(row.get("dst_port", 80)).isdigit() else 80
            b_sent = float(row.get("bytes_sent", 0))
            if port in (3333, 4444):
                labels.append("cloud_cryptomining")
            elif b_sent > 1000000:
                labels.append("cloud_storage_exfil")
            elif act == "REJECT":
                labels.append("cloud_port_scan")
            else:
                labels.append("normal")
        df["label"] = labels

    if sample_size and sample_size > 0 and len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)

    return df
