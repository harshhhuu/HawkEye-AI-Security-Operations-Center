"""
HawkEye-AI — Synthetic Log Generator

Generates a small fallback dataset mimicking the NSL-KDD schema so the
demo runs offline even when the real dataset files are unavailable.
"""

import random
import pandas as pd
from datetime import datetime, timedelta


# NSL-KDD protocol types, services, and flags
PROTOCOLS = ["tcp", "udp", "icmp"]
SERVICES = [
    "http", "smtp", "ftp", "ftp_data", "telnet", "ssh", "dns",
    "pop3", "imap4", "private", "other", "finger", "domain_u",
]
FLAGS = ["SF", "S0", "REJ", "RSTR", "RSTO", "SH", "S1", "S2", "S3", "OTH"]

# Attack categories and their characteristic patterns
ATTACK_PROFILES = {
    "normal": {
        "weight": 0.80,
        "bytes_sent_range": (0, 5000),
        "bytes_recv_range": (0, 10000),
        "duration_range": (0, 300),
        "count_range": (1, 20),
        "srv_count_range": (1, 20),
        "preferred_protocols": ["tcp", "udp"],
        "preferred_services": ["http", "smtp", "dns", "ssh"],
        "preferred_flags": ["SF"],
    },
    "dos": {
        "weight": 0.08,
        "bytes_sent_range": (0, 500),
        "bytes_recv_range": (0, 200),
        "duration_range": (0, 2),
        "count_range": (100, 511),
        "srv_count_range": (50, 511),
        "preferred_protocols": ["tcp", "icmp"],
        "preferred_services": ["http", "telnet", "private", "other"],
        "preferred_flags": ["S0", "REJ", "RSTO"],
    },
    "probe": {
        "weight": 0.06,
        "bytes_sent_range": (0, 1000),
        "bytes_recv_range": (0, 500),
        "duration_range": (0, 10),
        "count_range": (1, 100),
        "srv_count_range": (1, 50),
        "preferred_protocols": ["tcp", "icmp", "udp"],
        "preferred_services": ["finger", "telnet", "ftp", "private", "other"],
        "preferred_flags": ["SF", "S0", "REJ", "RSTR"],
    },
    "r2l": {
        "weight": 0.03,
        "bytes_sent_range": (100, 10000),
        "bytes_recv_range": (0, 50000),
        "duration_range": (1, 600),
        "count_range": (1, 10),
        "srv_count_range": (1, 10),
        "preferred_protocols": ["tcp"],
        "preferred_services": ["ftp", "telnet", "imap4", "pop3", "smtp"],
        "preferred_flags": ["SF", "SH", "S1"],
    },
    "u2r": {
        "weight": 0.03,
        "bytes_sent_range": (0, 3000),
        "bytes_recv_range": (0, 5000),
        "duration_range": (1, 300),
        "count_range": (1, 5),
        "srv_count_range": (1, 5),
        "preferred_protocols": ["tcp"],
        "preferred_services": ["telnet", "ftp", "ssh", "other"],
        "preferred_flags": ["SF", "S1", "S2"],
    },
}


def _random_ip() -> str:
    """Generate a random private-range IP address."""
    return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"


def _generate_row(label: str, profile: dict, base_time: datetime) -> dict:
    """Generate a single synthetic log row based on an attack profile."""
    protocol = random.choice(profile["preferred_protocols"])
    service = random.choice(profile["preferred_services"])
    flag = random.choice(profile["preferred_flags"])

    duration = random.randint(*profile["duration_range"])
    bytes_sent = random.randint(*profile["bytes_sent_range"])
    bytes_recv = random.randint(*profile["bytes_recv_range"])
    count = random.randint(*profile["count_range"])
    srv_count = random.randint(*profile["srv_count_range"])

    # Binary features — roughly plausible
    logged_in = 1 if label == "normal" and random.random() > 0.3 else 0
    root_shell = 1 if label == "u2r" and random.random() > 0.5 else 0
    su_attempted = 1 if label == "u2r" and random.random() > 0.7 else 0
    num_failed_logins = (
        random.randint(0, 5) if label in ("r2l", "u2r") else 0
    )

    return {
        "duration": duration,
        "protocol_type": protocol,
        "service": service,
        "flag": flag,
        "src_bytes": bytes_sent,
        "dst_bytes": bytes_recv,
        "land": 0,
        "wrong_fragment": random.randint(0, 3) if label == "dos" else 0,
        "urgent": 0,
        "hot": random.randint(0, 5) if label in ("r2l", "u2r") else 0,
        "num_failed_logins": num_failed_logins,
        "logged_in": logged_in,
        "num_compromised": random.randint(0, 3) if label in ("r2l", "u2r") else 0,
        "root_shell": root_shell,
        "su_attempted": su_attempted,
        "num_root": random.randint(0, 5) if label == "u2r" else 0,
        "num_file_creations": random.randint(0, 2) if label == "u2r" else 0,
        "num_shells": random.randint(0, 2) if label == "u2r" else 0,
        "num_access_files": random.randint(0, 3) if label in ("r2l", "u2r") else 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 1 if label == "r2l" and random.random() > 0.7 else 0,
        "count": count,
        "srv_count": srv_count,
        "serror_rate": round(random.uniform(0.8, 1.0), 2) if label == "dos" else round(random.uniform(0, 0.1), 2),
        "srv_serror_rate": round(random.uniform(0.8, 1.0), 2) if label == "dos" else round(random.uniform(0, 0.1), 2),
        "rerror_rate": round(random.uniform(0.5, 1.0), 2) if label == "probe" else round(random.uniform(0, 0.05), 2),
        "srv_rerror_rate": round(random.uniform(0.5, 1.0), 2) if label == "probe" else round(random.uniform(0, 0.05), 2),
        "same_srv_rate": round(random.uniform(0.0, 0.3), 2) if label in ("dos", "probe") else round(random.uniform(0.8, 1.0), 2),
        "diff_srv_rate": round(random.uniform(0.5, 1.0), 2) if label == "probe" else round(random.uniform(0, 0.1), 2),
        "srv_diff_host_rate": round(random.uniform(0, 1), 2),
        "dst_host_count": random.randint(0, 255),
        "dst_host_srv_count": random.randint(0, 255),
        "dst_host_same_srv_rate": round(random.uniform(0, 1), 2),
        "dst_host_diff_srv_rate": round(random.uniform(0, 1), 2),
        "dst_host_same_src_port_rate": round(random.uniform(0, 1), 2),
        "dst_host_srv_diff_host_rate": round(random.uniform(0, 1), 2),
        "dst_host_serror_rate": round(random.uniform(0, 1), 2),
        "dst_host_srv_serror_rate": round(random.uniform(0, 1), 2),
        "dst_host_rerror_rate": round(random.uniform(0, 1), 2),
        "dst_host_srv_rerror_rate": round(random.uniform(0, 1), 2),
        "label": label,
        "difficulty_level": random.randint(1, 21),
        # Extra columns for the dashboard
        "timestamp": base_time.isoformat(),
        "src": _random_ip(),
        "dst": _random_ip(),
    }


def generate_synthetic(n: int = 500, seed: int = 42) -> pd.DataFrame:
    """
    Generate a synthetic dataset mimicking NSL-KDD schema.

    Args:
        n:    Number of rows to generate.
        seed: Random seed for reproducibility.

    Returns:
        pd.DataFrame with NSL-KDD-compatible columns plus timestamp, src, dst.
    """
    random.seed(seed)
    base_time = datetime(2026, 9, 1, 0, 0, 0)

    rows = []
    for i in range(n):
        # Pick a label based on attack profile weights
        r = random.random()
        cumulative = 0.0
        chosen_label = "normal"
        for label, profile in ATTACK_PROFILES.items():
            cumulative += profile["weight"]
            if r <= cumulative:
                chosen_label = label
                break

        row_time = base_time + timedelta(seconds=i * random.randint(1, 30))
        row = _generate_row(chosen_label, ATTACK_PROFILES[chosen_label], row_time)
        rows.append(row)

    df = pd.DataFrame(rows)
    return df


if __name__ == "__main__":
    import os

    df = generate_synthetic(500)
    out_path = os.path.join(os.path.dirname(__file__), "synthetic_logs.csv")
    df.to_csv(out_path, index=False)
    print(f"Generated {len(df)} synthetic log entries -> {out_path}")
    print(f"Label distribution:\n{df['label'].value_counts()}")
