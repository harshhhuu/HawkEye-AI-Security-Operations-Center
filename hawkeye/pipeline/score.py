"""
HawkEye-AI — Risk Scoring

Combines anomaly likelihood with an impact heuristic to produce a 1-5
severity rating for each flagged alert.
"""

import numpy as np
import pandas as pd


# Services considered higher-risk (common attack targets)
HIGH_RISK_SERVICES = {
    "telnet", "ftp", "ftp_data", "ssh", "finger",
    "pop3", "imap4", "login", "exec", "shell",
}
MEDIUM_RISK_SERVICES = {
    "http", "smtp", "dns", "domain_u", "private",
}

# Byte thresholds for impact scoring
HIGH_BYTES_THRESHOLD = 10000
VERY_HIGH_BYTES_THRESHOLD = 50000


def risk_score(row: pd.Series) -> int:
    """
    Compute a risk severity score (1-5) for a single log entry.

    Combines:
        - Likelihood: derived from the anomaly_score magnitude
          (more negative = higher likelihood of being a true anomaly).
        - Impact: heuristic based on service type, bytes transferred,
          and connection characteristics.

    Formula:
        severity = clamp(round(likelihood * 0.6 + impact * 0.4), 1, 5)

    Args:
        row: A Series containing at least 'anomaly_score' and ideally
             'bytes_sent', 'bytes_recv', 'service'/'service_original'.

    Returns:
        Integer severity from 1 (low) to 5 (critical).
    """
    # --- Likelihood component (from anomaly score) ---
    anomaly_score = row.get("anomaly_score", 0)

    # Normalize anomaly_score to a 1-5 scale
    # Typical range: ~-0.5 (very anomalous) to ~+0.3 (very normal)
    # We map: -0.5 -> 5, -0.3 -> 4, -0.1 -> 3, 0 -> 2, >0 -> 1
    if anomaly_score <= -0.4:
        likelihood = 5.0
    elif anomaly_score <= -0.25:
        likelihood = 4.0
    elif anomaly_score <= -0.1:
        likelihood = 3.0
    elif anomaly_score <= 0:
        likelihood = 2.0
    else:
        likelihood = 1.0

    # --- Impact component ---
    impact = 1.0

    # Service risk
    service = str(
        row.get("service_original", row.get("service", ""))
    ).lower().strip()

    if service in HIGH_RISK_SERVICES:
        impact += 1.5
    elif service in MEDIUM_RISK_SERVICES:
        impact += 0.5

    # Bytes transferred — large transfers indicate potential data exfiltration
    bytes_sent = row.get("bytes_sent", row.get("src_bytes", 0))
    bytes_recv = row.get("bytes_recv", row.get("dst_bytes", 0))
    total_bytes = (bytes_sent or 0) + (bytes_recv or 0)

    if total_bytes >= VERY_HIGH_BYTES_THRESHOLD:
        impact += 2.0
    elif total_bytes >= HIGH_BYTES_THRESHOLD:
        impact += 1.0
    elif total_bytes >= 1000:
        impact += 0.5

    # Failed logins
    failed_logins = row.get("num_failed_logins", 0)
    if failed_logins and failed_logins > 0:
        impact += min(failed_logins * 0.3, 1.5)

    # Root shell / su attempted
    if row.get("root_shell", 0) == 1:
        impact += 1.5
    if row.get("su_attempted", 0) == 1:
        impact += 1.0

    # Cap impact at 5
    impact = min(impact, 5.0)

    # --- Combine ---
    severity = round(likelihood * 0.6 + impact * 0.4)
    return int(np.clip(severity, 1, 5))


def apply_risk_scores(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply risk scoring to all rows in the DataFrame.

    Flagged rows get a severity score (1-5); unflagged rows get severity 0.

    Args:
        df: DataFrame with 'is_flagged' and 'anomaly_score' columns.

    Returns:
        DataFrame with a new 'severity' column.
    """
    result = df.copy()

    result["severity"] = 0
    flagged_mask = result["is_flagged"] == True  # noqa: E712

    if flagged_mask.any():
        result.loc[flagged_mask, "severity"] = result.loc[flagged_mask].apply(
            risk_score, axis=1
        )

    return result
