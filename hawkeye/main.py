"""
HawkEye-AI — Main Pipeline Orchestrator

Runs the full pipeline end-to-end:
    1. Load data (NSL-KDD or synthetic fallback)
    2. Ingest & hash
    3. Detect anomalies
    4. Score risk
    5. Generate LLM explanations
    6. Write alerts.json

Usage:
    python main.py [--data-path PATH] [--max-explain N]
"""

import os
import sys
import json
import argparse
from datetime import datetime

# Add project root to path so imports work when run directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data.loader import try_load, load_logs
from pipeline.ingest import ingest
from pipeline.detect import detect_anomalies
from pipeline.score import apply_risk_scores
from pipeline.explain import explain_alerts
from pipeline.threat_intel import map_mitre_and_cia
from pipeline.geoip import enrich_alert_geo
from pipeline.playbooks import generate_playbook
from pipeline.benchmark import evaluate_isolation_forest, train_and_evaluate_supervised_rf


def run_pipeline(
    data_path: str = None,
    data_fmt: str = None,
    sample_size: int = 2000,
    max_explain: int = None,
    output_path: str = None,
) -> dict:
    """
    Execute the full HawkEye-AI pipeline.

    Args:
        data_path:   Path to a specific data file, or None for auto-detect.
        data_fmt:    Format ('unsw-nb15', 'nsl-kdd', 'csv', or 'auto').
        sample_size: Number of records to sample (default: 2000). Set to 0 for full dataset.
        max_explain: Max alerts to explain via LLM (None = all).
        output_path: Where to write alerts.json. Defaults to project root.

    Returns:
        Summary dict with pipeline statistics.
    """
    project_root = os.path.dirname(os.path.abspath(__file__))

    if output_path is None:
        output_path = os.path.join(project_root, "alerts.json")

    effective_sample = None if (sample_size == 0 or sample_size is None) else sample_size

    print("=" * 60)
    print("  HawkEye-AI — AI-Assisted Log Triage Pipeline")
    print("=" * 60)
    print()

    # --- Step 1: Load Data ---
    print("[1/5] Loading log data...")
    if data_fmt in ("aws-cloud", "aws-vpc") and not data_path:
        data_path = os.path.join(project_root, "data", "aws_cloud_sample.csv")

    if data_path:
        fmt = data_fmt or "auto"
        df = load_logs(data_path, fmt=fmt, sample_size=effective_sample)
    else:
        df = try_load(os.path.join(project_root, "data"), sample_size=effective_sample)

    print(f"       Loaded {len(df)} log entries.")
    if "label" in df.columns:
        print(f"       Labels: {df['label'].value_counts().to_dict()}")
    print()

    # --- Step 2: Ingest & Hash ---
    print("[2/5] Ingesting & computing batch hash...")
    clean_df, batch_hash = ingest(df)
    print(f"       Batch hash: {batch_hash[:16]}...")
    print(f"       Clean records: {len(clean_df)}")
    print()

    # --- Step 3: Detect Anomalies ---
    print("[3/5] Running anomaly detection (Isolation Forest)...")
    detected_df = detect_anomalies(clean_df)
    flagged_count = detected_df["is_flagged"].sum()
    print(f"       Flagged: {flagged_count} / {len(detected_df)} entries")
    print()

    # --- Step 4: Risk Scoring ---
    print("[4/5] Scoring risk severity...")
    scored_df = apply_risk_scores(detected_df)
    if flagged_count > 0:
        severity_dist = (
            scored_df[scored_df["is_flagged"]]
            ["severity"]
            .value_counts()
            .sort_index()
            .to_dict()
        )
        print(f"       Severity distribution: {severity_dist}")
    print()

    # --- Step 5: LLM Explanations ---
    print("[5/5] Generating alert explanations...")
    explained_df = explain_alerts(scored_df, max_explain=max_explain)
    print()

    # --- Write Output ---
    print("Writing alerts.json...")

    # Build the output — flagged alerts only, plus metadata
    flagged_alerts = explained_df[explained_df["is_flagged"] == True].copy()  # noqa

    # Convert to serializable format
    alerts_list = []
    for _, row in flagged_alerts.iterrows():
        alert = {
            "timestamp": str(row.get("timestamp", "")),
            "src": str(row.get("src", "")),
            "dst": str(row.get("dst", "")),
            "protocol": str(row.get("protocol_type_original", row.get("protocol_type", ""))),
            "service": str(row.get("service_original", row.get("service", ""))),
            "flag": str(row.get("flag_original", row.get("flag", ""))),
            "bytes_sent": int(row.get("bytes_sent", 0)),
            "bytes_recv": int(row.get("bytes_recv", 0)),
            "anomaly_score": round(float(row.get("anomaly_score", 0)), 4),
            "severity": int(row.get("severity", 0)),
            "explanation": str(row.get("explanation", "")),
            "label": str(row.get("label", "")),
        }
        # Step 1: Enrich with MITRE ATT&CK & CIA Triad
        mitre_cia = map_mitre_and_cia(row.to_dict())
        alert.update(mitre_cia)

        # Bonus: Enrich with GeoIP Threat Intelligence
        geo = enrich_alert_geo(alert)
        alert.update(geo)

        # Step 3: Generate Incident Response Playbook & Firewall Rules
        alert["playbook"] = generate_playbook(alert)

        alerts_list.append(alert)

    # Step 2: Compute AI / ML Benchmarks if ground truth labels exist
    benchmarks = {}
    if "label" in detected_df.columns:
        print("[*] Calculating ML model evaluation benchmarks...")
        iso_metrics = evaluate_isolation_forest(detected_df)
        rf_metrics = train_and_evaluate_supervised_rf(detected_df)
        benchmarks = {
            "isolation_forest": iso_metrics,
            "random_forest": rf_metrics,
        }

    output = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "total_logs_processed": len(df),
            "total_flagged": len(alerts_list),
            "batch_hash": batch_hash,
            "benchmarks": benchmarks,
        },
        "alerts": alerts_list,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"       Wrote {len(alerts_list)} alerts to {output_path}")
    print()
    print("=" * 60)
    print("  Pipeline complete!")
    print(f"  Total processed: {len(df)}  |  Flagged: {len(alerts_list)}")
    print("=" * 60)

    return output["metadata"]


def main():
    parser = argparse.ArgumentParser(
        description="HawkEye-AI — Run the full log triage pipeline."
    )
    parser.add_argument(
        "--data-path",
        type=str,
        default=None,
        help="Path to a specific data file (NSL-KDD .txt or .csv).",
    )
    parser.add_argument(
        "--data-fmt",
        type=str,
        default=None,
        choices=["unsw-nb15", "nsl-kdd", "aws-cloud", "aws-vpc", "csv", "auto"],
        help="Data format: unsw-nb15, nsl-kdd, aws-cloud, aws-vpc, or auto.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=2000,
        help="Number of log records to sample (default: 2000, use 0 for full dataset).",
    )
    parser.add_argument(
        "--max-explain",
        type=int,
        default=None,
        help="Max alerts to explain via LLM (default: all flagged).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output path for alerts.json.",
    )

    args = parser.parse_args()

    run_pipeline(
        data_path=args.data_path,
        data_fmt=args.data_fmt,
        sample_size=args.sample_size,
        max_explain=args.max_explain,
        output_path=args.output,
    )


if __name__ == "__main__":
    main()
