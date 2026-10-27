"""
HawkEye-AI — Unit Tests for Cloud Computing & AWS Features

Tests:
  - AWS Cloud Telemetry generation and schema validation
  - AWS VPC Flow Log loader and parser
  - Cloud-specific MITRE ATT&CK & CIA Triad mapping
  - Automated AWS SOAR Remediation (EC2 quarantine, IAM revocation, S3 block, NACL drop)
  - AWS S3 Archival with KMS and SHA-256 batch integrity hash
"""

import os
import sys
import pytest
import pandas as pd

# Add project root to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from data.cloud_telemetry import generate_aws_cloud_dataset, load_aws_vpc_flow_logs
from pipeline.threat_intel import map_mitre_and_cia
from cloud.aws_remediation import AWSRemediationEngine
from cloud.aws_s3 import archive_alerts_to_s3


class TestCloudTelemetry:
    """Tests for AWS Cloud Telemetry generation and parsing."""

    def test_generate_aws_cloud_dataset_schema(self):
        df = generate_aws_cloud_dataset(n=50, seed=42)
        assert len(df) == 50
        assert "cloud_provider" in df.columns
        assert "aws_region" in df.columns
        assert "vpc_id" in df.columns
        assert "instance_id" in df.columns
        assert "action" in df.columns
        assert "bytes_sent" in df.columns
        assert "bytes_recv" in df.columns
        assert "protocol_type" in df.columns
        assert "service" in df.columns

    def test_cloud_attacks_generated(self):
        df = generate_aws_cloud_dataset(n=200, seed=42)
        unique_labels = set(df["label"].unique())
        # Should include cloud-specific attacks
        assert any(l in unique_labels for l in ["cloud_port_scan", "cloud_storage_exfil", "cloud_cryptomining"])


class TestCloudThreatIntel:
    """Tests for MITRE ATT&CK Cloud Matrix mapping."""

    def test_s3_exfiltration_mapping(self):
        alert = {"label": "cloud_storage_exfil", "service": "https", "bytes_sent": 5000000}
        intel = map_mitre_and_cia(alert)
        assert intel["mitre_technique_id"] == "T1530"
        assert intel["cia_impact"] == "Confidentiality"
        assert "Cloud Storage" in intel["mitre_technique_name"]

    def test_cryptomining_mapping(self):
        alert = {"label": "cloud_cryptomining", "service": "cryptomining"}
        intel = map_mitre_and_cia(alert)
        assert intel["mitre_technique_id"] == "T1496"
        assert intel["cia_impact"] == "Availability"
        assert "Cryptomining" in intel["mitre_technique_name"]

    def test_iam_privilege_escalation_mapping(self):
        alert = {"label": "iam_privilege_escalation", "service": "https"}
        intel = map_mitre_and_cia(alert)
        assert intel["mitre_technique_id"] == "T1078.004"
        assert intel["cia_impact"] == "Integrity"


class TestAWSRemediationEngine:
    """Tests for automated AWS Boto3 Cloud SOAR mitigations."""

    def setup_method(self):
        self.engine = AWSRemediationEngine(region="us-east-1", force_simulation=True)

    def test_ec2_quarantine_simulation(self):
        receipt = self.engine.quarantine_ec2_instance("i-0a87612f0b9e812d4", "vpc-07e15fa8c9b421a10", dry_run=True)
        assert receipt["status"] == "SUCCESS"
        assert receipt["action"] == "EC2_QUARANTINE_ISOLATION"
        assert receipt["instance_id"] == "i-0a87612f0b9e812d4"
        assert "sg-0999quarantine999" in receipt["quarantine_sg"]

    def test_iam_credential_revocation(self):
        receipt = self.engine.revoke_iam_credentials("developer-temp", "AKIAIOSFODNN7EXAMPLE", dry_run=True)
        assert receipt["status"] == "SUCCESS"
        assert receipt["action"] == "IAM_KEY_REVOCATION"
        assert receipt["new_status"] == "Inactive"

    def test_s3_public_lockdown(self):
        receipt = self.engine.block_s3_public_access("hawkeye-finance-records-2026", dry_run=True)
        assert receipt["status"] == "SUCCESS"
        assert receipt["action"] == "S3_PUBLIC_LOCKDOWN"

    def test_vpc_nacl_block(self):
        receipt = self.engine.block_vpc_nacl_ip("acl-09823412", "185.220.101.5", dry_run=True)
        assert receipt["status"] == "SUCCESS"
        assert receipt["action"] == "VPC_NACL_INGRESS_DROP"
        assert receipt["blocked_cidr"] == "185.220.101.5/32"


class TestS3Archival:
    """Tests for S3 archival with cryptographic hash."""

    def test_archive_alerts_to_s3(self):
        sample_batch = {
            "metadata": {"batch_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            "alerts": [{"src": "10.0.1.5", "dst": "10.0.1.25", "severity": 4}],
        }
        receipt = archive_alerts_to_s3(sample_batch, bucket_name="hawkeye-soc-archives", dry_run=True)
        assert receipt["status"] == "SUCCESS"
        assert receipt["server_side_encryption"] == "aws:kms"
        assert "s3://hawkeye-soc-archives/" in receipt["s3_uri"]
        assert receipt["alert_count"] == 1
