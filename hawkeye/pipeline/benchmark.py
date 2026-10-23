"""
HawkEye-AI — Machine Learning Evaluation & Benchmarking Module

Compares Unsupervised Isolation Forest vs. Supervised Random Forest
against ground-truth labels (UNSW-NB15 / NSL-KDD):
  - Confusion Matrix (TP, FP, TN, FN)
  - Precision, Recall, F1-Score, Accuracy, Specificity
  - False Positive Rate (FPR) & ROC-AUC
"""

from typing import Dict, Any, Tuple
import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    roc_auc_score,
)
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from pipeline.detect import DETECTION_FEATURES


def evaluate_isolation_forest(
    df: pd.DataFrame,
) -> Dict[str, Any]:
    """
    Evaluate Isolation Forest predictions against ground truth labels.

    Args:
        df: DataFrame containing 'is_flagged', 'anomaly_score', and 'label'.

    Returns:
        Dict of evaluation metrics and confusion matrix breakdown.
    """
    if "label" not in df.columns or "is_flagged" not in df.columns:
        return {"error": "DataFrame missing 'label' or 'is_flagged' columns."}

    # Derive binary ground truth: 1 for attack, 0 for normal
    y_true = df["label"].astype(str).str.lower().apply(
        lambda x: 0 if x in ("0", "normal", "benign") else 1
    ).values

    # Predicted binary: 1 for flagged (anomalous), 0 for inlier (normal)
    y_pred = df["is_flagged"].astype(int).values

    # Confusion matrix: tn, fp, fn, tp
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    total = len(y_true)
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # Invert anomaly_score for ROC-AUC (lower decision_function = higher probability of attack)
    if "anomaly_score" in df.columns:
        scores = -df["anomaly_score"].values
        try:
            auc = roc_auc_score(y_true, scores)
        except Exception:
            auc = 0.5
    else:
        auc = 0.5

    return {
        "model_name": "Isolation Forest (Unsupervised)",
        "model_type": "Unsupervised Ensemble",
        "total_samples": total,
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "specificity": round(float(specificity), 4),
        "false_positive_rate": round(float(fpr), 4),
        "roc_auc": round(float(auc), 4),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def train_and_evaluate_supervised_rf(
    df: pd.DataFrame,
    test_size: float = 0.3,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Train and evaluate a supervised Random Forest classifier as an academic benchmark.

    Args:
        df: DataFrame with numeric detection features and 'label'.

    Returns:
        Dict of evaluation metrics on the hold-out test set.
    """
    if "label" not in df.columns:
        return {"error": "DataFrame missing 'label' column."}

    available_features = [f for f in DETECTION_FEATURES if f in df.columns]
    if not available_features:
        return {"error": "No detection features available."}

    X = df[available_features].fillna(0).values
    y = df["label"].astype(str).str.lower().apply(
        lambda x: 0 if x in ("0", "normal", "benign") else 1
    ).values

    if len(np.unique(y)) < 2:
        return {"error": "Dataset must contain at least two classes (normal and attack)."}

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    rf = RandomForestClassifier(
        n_estimators=60,
        max_depth=12,
        random_state=random_state,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    y_prob = rf.predict_proba(X_test)[:, 1]

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    try:
        auc = roc_auc_score(y_test, y_prob)
    except Exception:
        auc = 0.5

    # Top feature importances
    importances = sorted(
        zip(available_features, rf.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )[:5]

    return {
        "model_name": "Random Forest (Supervised Baseline)",
        "model_type": "Supervised Tree Ensemble",
        "total_samples": len(y_test),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "specificity": round(float(specificity), 4),
        "false_positive_rate": round(float(fpr), 4),
        "roc_auc": round(float(auc), 4),
        "top_features": [(feat, round(float(imp), 4)) for feat, imp in importances],
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }
