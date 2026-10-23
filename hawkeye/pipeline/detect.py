"""
HawkEye-AI — Anomaly Detection

Uses scikit-learn's Isolation Forest to flag anomalous network log entries.
"""

import pandas as pd
from sklearn.ensemble import IsolationForest


# Numeric features used for anomaly detection
DETECTION_FEATURES = [
    "duration",
    "bytes_sent", "bytes_recv",
    "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in",
    "count", "srv_count",
    "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate",
    "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]


def detect_anomalies(
    df: pd.DataFrame,
    contamination: float = 0.15,
    random_state: int = 42,
) -> pd.DataFrame:
    """
    Fit an Isolation Forest on numeric features and flag anomalies.

    Args:
        df:            Cleaned DataFrame from the ingestion stage.
        contamination: Expected proportion of anomalies in the data.
        random_state:  Seed for reproducibility.

    Returns:
        The input DataFrame with two new columns appended:
            - anomaly_score (float): raw decision function score from
              Isolation Forest (more negative = more anomalous).
            - is_flagged (bool): True for entries classified as anomalous.
    """
    result = df.copy()

    # Select only features that exist in this DataFrame
    available_features = [f for f in DETECTION_FEATURES if f in result.columns]

    if not available_features:
        raise ValueError(
            "No detection features found in DataFrame. "
            f"Expected at least some of: {DETECTION_FEATURES[:5]}"
        )

    X = result[available_features].values

    # Fit Isolation Forest
    iso_forest = IsolationForest(
        contamination=contamination,
        random_state=random_state,
        n_estimators=100,
        n_jobs=-1,
    )
    iso_forest.fit(X)

    # decision_function: higher = more normal, lower = more anomalous
    # predict: +1 for inliers, -1 for outliers
    result["anomaly_score"] = iso_forest.decision_function(X)
    predictions = iso_forest.predict(X)
    result["is_flagged"] = predictions == -1

    return result
