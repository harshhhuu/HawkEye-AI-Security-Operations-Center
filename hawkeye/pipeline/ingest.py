"""
HawkEye-AI — Log Ingestion & Integrity Hashing

Cleans/normalizes ingested log DataFrames and computes SHA-256 hashes
for tamper detection.
"""

import hashlib
import pandas as pd
from sklearn.preprocessing import LabelEncoder


# Categorical columns that need encoding for ML
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]


def _compute_hash(df: pd.DataFrame) -> str:
    """
    Compute a deterministic SHA-256 hash of a DataFrame's content.

    The DataFrame is sorted by all columns, converted to a canonical
    string representation, and hashed. This ensures the same logical
    data always produces the same hash regardless of row order.
    """
    # Select only the feature columns (exclude metadata like timestamp, src, dst)
    hash_cols = [c for c in df.columns if c not in ("timestamp", "src", "dst")]
    subset = df[hash_cols].copy()

    # Sort by all columns for determinism
    subset = subset.sort_values(by=list(subset.columns)).reset_index(drop=True)

    # Convert to a canonical string and hash
    canonical = subset.to_csv(index=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def ingest(df: pd.DataFrame) -> tuple:
    """
    Clean, normalize, and hash a batch of log data.

    Steps:
        1. Drop duplicate rows.
        2. Fill missing numeric values with 0, categorical with 'unknown'.
        3. Encode categorical features (protocol, service, flag) as integers,
           storing original values in *_original columns.
        4. Compute a SHA-256 batch hash for integrity verification.

    Args:
        df: Raw log DataFrame from the loader.

    Returns:
        (clean_df, batch_hash) where clean_df has encoded categoricals
        and batch_hash is the SHA-256 hex digest of the canonical batch.
    """
    clean = df.copy()

    # 1. Drop duplicates
    clean = clean.drop_duplicates().reset_index(drop=True)

    # 2. Handle missing values
    numeric_cols = clean.select_dtypes(include="number").columns
    clean[numeric_cols] = clean[numeric_cols].fillna(0)

    for col in CATEGORICAL_COLS:
        if col in clean.columns:
            clean[col] = clean[col].fillna("unknown")

    # Compute hash BEFORE encoding (on human-readable data)
    batch_hash = _compute_hash(clean)

    # 3. Encode categorical columns
    encoders = {}
    for col in CATEGORICAL_COLS:
        if col in clean.columns:
            # Preserve original values for display/explanation
            clean[f"{col}_original"] = clean[col].copy()

            le = LabelEncoder()
            clean[col] = le.fit_transform(clean[col].astype(str))
            encoders[col] = le

    return clean, batch_hash


def verify_batch(df: pd.DataFrame, expected_hash: str) -> bool:
    """
    Verify log batch integrity by recomputing its hash.

    Decodes any label-encoded categorical columns back to their original
    values before hashing, so the comparison is consistent with the hash
    computed at ingestion time.

    Args:
        df:            The DataFrame to verify.
        expected_hash: The SHA-256 hash from the original ingestion.

    Returns:
        True if the batch is unmodified, False if tampering is detected.
    """
    verify_df = df.copy()

    # Restore original categorical values if encoded versions exist
    for col in CATEGORICAL_COLS:
        orig_col = f"{col}_original"
        if orig_col in verify_df.columns:
            verify_df[col] = verify_df[orig_col]
            verify_df = verify_df.drop(columns=[orig_col])

    # Drop any columns added by the pipeline (anomaly scores, etc.)
    pipeline_cols = [
        "anomaly_score", "is_flagged", "severity", "explanation",
        "protocol_type_original", "service_original", "flag_original",
    ]
    for col in pipeline_cols:
        if col in verify_df.columns:
            verify_df = verify_df.drop(columns=[col])

    actual_hash = _compute_hash(verify_df)
    return actual_hash == expected_hash
