"""
HawkEye-AI — Log Loader

Loads security log data from NSL-KDD dataset files or a synthetic CSV
fallback into a standardized pandas DataFrame.
"""

import os
import pandas as pd


# The 41 standard NSL-KDD feature names (in column order) + label + difficulty
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login",
    "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty_level",
]

# Mapping of specific attack labels to their categories
ATTACK_CATEGORY_MAP = {
    "normal": "normal",
    # DoS attacks
    "back": "dos", "land": "dos", "neptune": "dos", "pod": "dos",
    "smurf": "dos", "teardrop": "dos", "apache2": "dos",
    "udpstorm": "dos", "processtable": "dos", "mailbomb": "dos",
    # Probe attacks
    "satan": "probe", "ipsweep": "probe", "nmap": "probe",
    "portsweep": "probe", "mscan": "probe", "saint": "probe",
    # R2L attacks
    "guess_passwd": "r2l", "ftp_write": "r2l", "imap": "r2l",
    "phf": "r2l", "multihop": "r2l", "warezmaster": "r2l",
    "warezclient": "r2l", "spy": "r2l", "xlock": "r2l",
    "xsnoop": "r2l", "snmpguess": "r2l", "snmpgetattack": "r2l",
    "httptunnel": "r2l", "sendmail": "r2l", "named": "r2l",
    "worm": "r2l",
    # U2R attacks
    "buffer_overflow": "u2r", "loadmodule": "u2r", "rootkit": "u2r",
    "perl": "u2r", "sqlattack": "u2r", "xterm": "u2r", "ps": "u2r",
}


def _add_synthetic_metadata(df: pd.DataFrame) -> pd.DataFrame:
    """Add timestamp, src, and dst columns if they don't exist."""
    import random
    from datetime import datetime, timedelta

    random.seed(42)

    if "timestamp" not in df.columns:
        base = datetime(2026, 9, 1, 0, 0, 0)
        df["timestamp"] = [
            (base + timedelta(seconds=i * random.randint(1, 30))).isoformat()
            for i in range(len(df))
        ]

    if "src" not in df.columns:
        df["src"] = [
            f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            for _ in range(len(df))
        ]

    if "dst" not in df.columns:
        df["dst"] = [
            f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
            for _ in range(len(df))
        ]

    return df


def load_unsw_nb15(path: str, sample_size: int = None) -> pd.DataFrame:
    """
    Load and standardize modern UNSW-NB15 dataset logs.

    Maps UNSW-NB15 column names to HawkEye standard format:
      - proto      -> protocol_type
      - state      -> flag
      - sbytes     -> bytes_sent
      - dbytes     -> bytes_recv
      - dur        -> duration
      - attack_cat -> label (e.g. Generic, Exploits, Fuzzers, DoS, Reconnaissance, etc.)

    Args:
        path:        Path to UNSW_NB15 CSV file.
        sample_size: Optional stratified sample size (e.g. 2000). If None, loads all rows.

    Returns:
        Standardized DataFrame ready for the HawkEye pipeline.
    """
    df = pd.read_csv(path)

    # Standardize label columns: attack_cat holds the multi-class attack names
    if "attack_cat" in df.columns:
        if "label" in df.columns:
            df["binary_label"] = df["label"]
            df = df.drop(columns=["label"])
        df["label"] = df["attack_cat"].fillna("Normal").astype(str).str.strip().str.lower()
        df = df.drop(columns=["attack_cat"])
    elif "label" in df.columns:
        df["label"] = df["label"].astype(str).str.strip().str.lower()

    # Column mappings
    col_map = {
        "proto": "protocol_type",
        "state": "flag",
        "sbytes": "bytes_sent",
        "dbytes": "bytes_recv",
        "dur": "duration",
    }
    df = df.rename(columns={k: v for k, v in col_map.items() if k in df.columns})

    # Clean service column ('-' represents no specific registered service)
    if "service" in df.columns:
        df["service"] = df["service"].replace({"-": "other", "": "other"}).fillna("other")

    # Stratified sampling across attack categories if sample_size is requested
    if sample_size and sample_size > 0 and len(df) > sample_size:
        if "label" in df.columns:
            sampled_dfs = []
            for _, group in df.groupby("label", group_keys=False):
                group_sample_n = max(2, int(round(len(group) / len(df) * sample_size)))
                group_sample_n = min(group_sample_n, len(group))
                sampled_dfs.append(group.sample(n=group_sample_n, random_state=42))
            df = pd.concat(sampled_dfs, ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)
            if len(df) > sample_size:
                df = df.iloc[:sample_size].reset_index(drop=True)
        else:
            df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)

    df = _add_synthetic_metadata(df)
    return df


def load_logs(path: str, fmt: str = "auto", sample_size: int = None) -> pd.DataFrame:
    """
    Load security log data into a standardized DataFrame.

    Args:
        path:        Path to the data file (NSL-KDD .txt, UNSW-NB15 .csv, or generic .csv).
        fmt:         Format identifier — 'unsw-nb15', 'nsl-kdd', 'csv', or 'auto'.
        sample_size: Optional sample size for large datasets.

    Returns:
        pd.DataFrame with at least: timestamp, src, dst, protocol_type,
        service, flag, bytes_sent, bytes_recv, label (if present).
    """
    path_lower = path.lower()

    # Auto-detect format
    if fmt == "auto":
        if "unsw" in path_lower or "nb15" in path_lower:
            fmt = "unsw-nb15"
        elif path_lower.endswith(".txt") or "kdd" in path_lower:
            fmt = "nsl-kdd"
        else:
            fmt = "csv"

    if fmt == "unsw-nb15":
        return load_unsw_nb15(path, sample_size=sample_size)

    elif fmt == "nsl-kdd":
        df = pd.read_csv(path, header=None, names=NSL_KDD_COLUMNS)

        # Map specific attack names to categories
        df["label"] = (
            df["label"]
            .str.strip()
            .str.lower()
            .map(lambda x: ATTACK_CATEGORY_MAP.get(x, x))
        )

        # Rename bytes columns for consistency with the dashboard
        df = df.rename(columns={
            "src_bytes": "bytes_sent",
            "dst_bytes": "bytes_recv",
        })

        if sample_size and sample_size > 0 and len(df) > sample_size:
            df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)

        df = _add_synthetic_metadata(df)

    elif fmt == "csv":
        df = pd.read_csv(path)

        # Check if it has UNSW-NB15 columns despite being labeled 'csv'
        if "proto" in df.columns and "attack_cat" in df.columns:
            return load_unsw_nb15(path, sample_size=sample_size)

        # Normalize column names
        col_renames = {}
        if "src_bytes" in df.columns and "bytes_sent" not in df.columns:
            col_renames["src_bytes"] = "bytes_sent"
        if "dst_bytes" in df.columns and "bytes_recv" not in df.columns:
            col_renames["dst_bytes"] = "bytes_recv"
        if col_renames:
            df = df.rename(columns=col_renames)

        if sample_size and sample_size > 0 and len(df) > sample_size:
            df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)

        df = _add_synthetic_metadata(df)

    else:
        raise ValueError(f"Unsupported format: {fmt!r}. Use 'unsw-nb15', 'nsl-kdd', or 'csv'.")

    return df


def try_load(data_dir: str = None, sample_size: int = 2000) -> pd.DataFrame:
    """
    Attempt to load available security log datasets, prioritizing modern
    UNSW-NB15, then NSL-KDD, falling back to synthetic generation.

    Args:
        data_dir:    Directory to look for dataset files. Defaults to this module's directory.
        sample_size: Sampling cap for large datasets (e.g. 2000). Set to 0 or None for full.

    Returns:
        pd.DataFrame ready for the pipeline.
    """
    if data_dir is None:
        data_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. Try modern UNSW-NB15 dataset first
    unsw_candidates = [
        os.path.join(data_dir, "UNSW_NB15_testing-set.csv"),
        os.path.join(data_dir, "UNSW_NB15_training-set.csv"),
    ]
    for unsw_path in unsw_candidates:
        if os.path.exists(unsw_path):
            print(f"[loader] Loading modern UNSW-NB15 dataset from {unsw_path}")
            if sample_size and sample_size > 0:
                print(f"[loader] Using stratified sample of {sample_size} records across attack categories.")
            return load_unsw_nb15(unsw_path, sample_size=sample_size)

    # 2. Try NSL-KDD
    nsl_path = os.path.join(data_dir, "KDDTrain+.txt")
    if os.path.exists(nsl_path):
        print(f"[loader] Loading NSL-KDD dataset from {nsl_path}")
        return load_logs(nsl_path, fmt="nsl-kdd", sample_size=sample_size)

    # 3. Try synthetic CSV
    synth_path = os.path.join(data_dir, "synthetic_logs.csv")
    if os.path.exists(synth_path):
        print(f"[loader] Loading synthetic logs from {synth_path}")
        return load_logs(synth_path, fmt="csv")

    # 4. Generate synthetic on the fly
    print("[loader] No dataset found — generating synthetic logs...")
    from data.synthetic import generate_synthetic

    df = generate_synthetic(500)
    df.to_csv(synth_path, index=False)
    print(f"[loader] Saved synthetic logs to {synth_path}")
    return df
