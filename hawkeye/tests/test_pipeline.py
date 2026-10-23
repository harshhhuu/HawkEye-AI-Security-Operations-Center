"""
HawkEye-AI — Unit Tests

Tests for each pipeline stage:
  - Data loading (NSL-KDD format + synthetic fallback)
  - Ingestion & hashing (determinism, tamper detection)
  - Anomaly detection (column creation, flagging)
  - Risk scoring (range, ordering)
  - LLM explanation (mocked API call)
  - Role-based access control

Run:
    cd hawkeye
    pytest tests/test_pipeline.py -v
"""

import os
import sys
import json
import pytest
import pandas as pd
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from data.synthetic import generate_synthetic
from data.loader import load_logs, NSL_KDD_COLUMNS
from pipeline.ingest import ingest, verify_batch
from pipeline.detect import detect_anomalies
from pipeline.score import risk_score, apply_risk_scores
from pipeline.explain import explain_alert, PROMPT_TEMPLATE
from auth.roles import can_dismiss_alert, get_role_permissions


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def synthetic_df():
    """Generate a small synthetic dataset for testing."""
    return generate_synthetic(n=100, seed=42)


@pytest.fixture
def ingested_data(synthetic_df):
    """Run ingestion on the synthetic dataset."""
    clean_df, batch_hash = ingest(synthetic_df)
    return clean_df, batch_hash


@pytest.fixture
def detected_data(ingested_data):
    """Run anomaly detection on the ingested data."""
    clean_df, _ = ingested_data
    return detect_anomalies(clean_df)


@pytest.fixture
def scored_data(detected_data):
    """Apply risk scoring to the detected data."""
    return apply_risk_scores(detected_data)


# ---------------------------------------------------------------------------
# Test: Data Loading — Synthetic
# ---------------------------------------------------------------------------
class TestDataLoading:

    def test_load_logs_synthetic(self, synthetic_df):
        """Synthetic generator produces a valid DataFrame with expected schema."""
        assert isinstance(synthetic_df, pd.DataFrame)
        assert len(synthetic_df) == 100

        # Required columns must exist
        required_cols = [
            "duration", "protocol_type", "service", "flag",
            "src_bytes", "dst_bytes", "label", "timestamp", "src", "dst",
        ]
        for col in required_cols:
            assert col in synthetic_df.columns, f"Missing column: {col}"

    def test_synthetic_label_distribution(self, synthetic_df):
        """Synthetic data should contain a mix of normal and attack labels."""
        labels = synthetic_df["label"].unique()
        assert "normal" in labels, "Synthetic data should have 'normal' entries"
        assert len(labels) > 1, "Synthetic data should have at least one attack type"

    def test_load_logs_csv_format(self, tmp_path):
        """load_logs with fmt='csv' should read a CSV file correctly."""
        # Create a mini CSV
        df = generate_synthetic(n=10, seed=99)
        csv_path = tmp_path / "test.csv"
        df.to_csv(csv_path, index=False)

        loaded = load_logs(str(csv_path), fmt="csv")
        assert len(loaded) == 10
        assert "timestamp" in loaded.columns

    def test_load_unsw_nb15_format(self, tmp_path):
        """load_logs with fmt='unsw-nb15' should map UNSW-NB15 columns to standard format."""
        mini_unsw = pd.DataFrame({
            "proto": ["tcp", "udp", "tcp"],
            "service": ["http", "-", "ftp"],
            "state": ["FIN", "CON", "INT"],
            "sbytes": [500, 200, 1000],
            "dbytes": [1200, 0, 400],
            "dur": [0.5, 0.1, 1.2],
            "attack_cat": ["Normal", "Exploits", "DoS"],
            "label": [0, 1, 1],
        })
        csv_path = tmp_path / "UNSW_NB15_sample.csv"
        mini_unsw.to_csv(csv_path, index=False)

        loaded = load_logs(str(csv_path), fmt="unsw-nb15")
        assert len(loaded) == 3
        assert "protocol_type" in loaded.columns
        assert "bytes_sent" in loaded.columns
        assert "bytes_recv" in loaded.columns
        assert "duration" in loaded.columns
        assert "flag" in loaded.columns
        assert loaded["label"].tolist() == ["normal", "exploits", "dos"]
        assert loaded["service"].tolist() == ["http", "other", "ftp"]


# ---------------------------------------------------------------------------
# Test: Ingestion & Hashing
# ---------------------------------------------------------------------------
class TestIngestion:

    def test_ingest_hash(self, synthetic_df):
        """ingest() produces a deterministic hash — same input → same hash."""
        _, hash1 = ingest(synthetic_df)
        _, hash2 = ingest(synthetic_df)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex digest length

    def test_verify_batch_pass(self, ingested_data):
        """verify_batch returns True for an unmodified batch."""
        clean_df, batch_hash = ingested_data
        assert verify_batch(clean_df, batch_hash) is True

    def test_verify_batch_tamper(self, ingested_data):
        """Mutating one cell causes verify_batch to return False."""
        clean_df, batch_hash = ingested_data
        tampered = clean_df.copy()

        # Flip one numeric value
        tampered.iloc[0, tampered.columns.get_loc("duration")] = 999999

        assert verify_batch(tampered, batch_hash) is False


# ---------------------------------------------------------------------------
# Test: Anomaly Detection
# ---------------------------------------------------------------------------
class TestDetection:

    def test_detect_anomalies(self, ingested_data):
        """detect_anomalies adds anomaly_score and is_flagged columns."""
        clean_df, _ = ingested_data
        result = detect_anomalies(clean_df)

        assert "anomaly_score" in result.columns
        assert "is_flagged" in result.columns
        assert result["anomaly_score"].dtype == float
        assert result["is_flagged"].dtype == bool

    def test_some_rows_flagged(self, detected_data):
        """At least some rows should be flagged as anomalous."""
        flagged_count = detected_data["is_flagged"].sum()
        assert flagged_count > 0, "No rows were flagged — detection may be broken"
        assert flagged_count < len(detected_data), "All rows flagged — contamination too high"


# ---------------------------------------------------------------------------
# Test: Risk Scoring
# ---------------------------------------------------------------------------
class TestScoring:

    def test_risk_score_range(self, detected_data):
        """risk_score always returns an integer in [1, 5]."""
        flagged = detected_data[detected_data["is_flagged"]]
        for _, row in flagged.head(20).iterrows():
            score = risk_score(row)
            assert isinstance(score, int)
            assert 1 <= score <= 5, f"Score {score} out of range"

    def test_risk_score_ordering(self):
        """Higher anomaly + higher bytes → higher severity."""
        # Create two mock rows
        low_risk = pd.Series({
            "anomaly_score": 0.1,
            "bytes_sent": 100,
            "bytes_recv": 50,
            "service_original": "http",
            "num_failed_logins": 0,
            "root_shell": 0,
            "su_attempted": 0,
        })

        high_risk = pd.Series({
            "anomaly_score": -0.5,
            "bytes_sent": 100000,
            "bytes_recv": 200000,
            "service_original": "telnet",
            "num_failed_logins": 5,
            "root_shell": 1,
            "su_attempted": 1,
        })

        assert risk_score(high_risk) > risk_score(low_risk)

    def test_apply_risk_scores(self, scored_data):
        """apply_risk_scores adds a severity column."""
        assert "severity" in scored_data.columns

        # Unflagged rows should have severity 0
        unflagged = scored_data[scored_data["is_flagged"] == False]  # noqa
        if len(unflagged) > 0:
            assert (unflagged["severity"] == 0).all()


# ---------------------------------------------------------------------------
# Test: LLM Explanation (Mocked)
# ---------------------------------------------------------------------------
class TestExplanation:

    def test_explain_mock(self):
        """
        Mocks the Google Gemini API call; verifies the prompt template
        is filled correctly and the function returns a string explanation.
        """
        row = pd.Series({
            "protocol_type_original": "tcp",
            "service_original": "telnet",
            "flag_original": "S0",
            "bytes_sent": 0,
            "bytes_recv": 0,
            "anomaly_score": -0.35,
            "severity": 4,
        })

        mock_response = MagicMock()
        mock_response.text = "Suspicious SYN-only connection to telnet service suggests a port scan or probe attempt."

        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response

        mock_genai = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model

        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
            with patch("pipeline.explain.genai", mock_genai):
                # Clear both in-memory and on-disk cache to force an API call
                import pipeline.explain as explain_module
                explain_module._explanation_cache = {}
                cache_path = os.path.normpath(explain_module._CACHE_FILE)
                if os.path.exists(cache_path):
                    os.remove(cache_path)

                result = explain_alert(row)

                assert isinstance(result, str)
                assert len(result) > 10
                assert "telnet" in result.lower() or "suspicious" in result.lower()

                # Verify Gemini was configured and called with prompt
                mock_genai.configure.assert_called_once_with(api_key="test-key")
                mock_genai.GenerativeModel.assert_called_once_with(explain_module.GEMINI_MODEL)
                call_args = mock_model.generate_content.call_args
                assert call_args is not None
                prompt_arg = call_args[0][0] if call_args[0] else call_args.kwargs.get("contents", "")
                assert "telnet" in prompt_arg
                assert "S0" in prompt_arg

    def test_explain_no_api_key(self):
        """Without an API key, explain_alert returns the fallback message."""
        row = pd.Series({
            "protocol_type_original": "tcp",
            "service_original": "http",
            "flag_original": "SF",
            "bytes_sent": 1000,
            "bytes_recv": 2000,
            "anomaly_score": -0.2,
            "severity": 3,
        })

        # Clear cache and remove API key
        import pipeline.explain as explain_module
        explain_module._explanation_cache = {}

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GEMINI_API_KEY", None)
            result = explain_alert(row)

        assert "LLM unavailable" in result or "manual review" in result.lower()


# ---------------------------------------------------------------------------
# Test: Role-Based Access Control
# ---------------------------------------------------------------------------
class TestRoles:

    def test_role_admin(self):
        """Admin role can dismiss alerts."""
        assert can_dismiss_alert("admin") is True

    def test_role_viewer(self):
        """Viewer role cannot dismiss alerts."""
        assert can_dismiss_alert("viewer") is False

    def test_role_permissions_admin(self):
        """Admin has full permissions."""
        perms = get_role_permissions("admin")
        assert perms["can_dismiss"] is True
        assert perms["can_export"] is True
        assert perms["can_verify_integrity"] is True

    def test_role_permissions_viewer(self):
        """Viewer has limited permissions."""
        perms = get_role_permissions("viewer")
        assert perms["can_dismiss"] is False
        assert perms["can_export"] is False
        assert perms["can_verify_integrity"] is True


# ---------------------------------------------------------------------------
# Test: MITRE ATT&CK & CIA Triad Mapping
# ---------------------------------------------------------------------------
class TestThreatIntel:

    def test_dos_mitre_mapping(self):
        from pipeline.threat_intel import map_mitre_and_cia
        res = map_mitre_and_cia({"label": "dos", "service": "http"})
        assert res["cia_impact"] == "Availability"
        assert res["mitre_technique_id"] == "T1499"
        assert res["mitre_tactic"] == "Impact"

    def test_reconnaissance_mitre_mapping(self):
        from pipeline.threat_intel import map_mitre_and_cia
        res = map_mitre_and_cia({"label": "reconnaissance", "service": "other"})
        assert res["cia_impact"] == "Confidentiality"
        assert res["mitre_technique_id"] == "T1595"
        assert res["mitre_tactic"] == "Reconnaissance"

    def test_privilege_escalation_mapping(self):
        from pipeline.threat_intel import map_mitre_and_cia
        res = map_mitre_and_cia({"root_shell": 1, "label": "normal"})
        assert res["cia_impact"] == "Integrity"
        assert res["mitre_tactic"] == "Privilege Escalation"


# ---------------------------------------------------------------------------
# Test: Incident Response Playbooks & Firewall Rules
# ---------------------------------------------------------------------------
class TestPlaybooks:

    def test_generate_playbook(self):
        from pipeline.playbooks import generate_playbook
        alert = {
            "src": "192.168.1.100",
            "dst": "10.0.0.5",
            "protocol": "tcp",
            "service": "http",
            "severity": 4,
            "label": "exploits",
            "mitre_technique_id": "T1190",
            "mitre_technique_name": "Exploit Public-Facing Application",
        }
        playbook = generate_playbook(alert)
        assert "iptables -A INPUT -s 192.168.1.100" in playbook["iptables"]
        assert "revoke-security-group-ingress" in playbook["aws_cli"]
        assert "drop tcp 192.168.1.100" in playbook["snort_rule"]
        assert len(playbook["steps"]) == 4
        assert "#!/usr/bin/env bash" in playbook["remediation_script"]


# ---------------------------------------------------------------------------
# Test: GeoIP Threat Intelligence
# ---------------------------------------------------------------------------
class TestGeoIP:

    def test_enrich_ip_geo(self):
        from pipeline.geoip import enrich_ip_geo, enrich_alert_geo
        geo = enrich_ip_geo("192.168.1.50")
        assert "country" in geo
        assert "lat" in geo
        assert "lon" in geo

        alert_geo = enrich_alert_geo({"src": "192.168.1.50", "dst": "10.0.0.1", "severity": 3})
        assert "src_country" in alert_geo
        assert "threat_reputation_score" in alert_geo
        assert 0 <= alert_geo["threat_reputation_score"] <= 100


# ---------------------------------------------------------------------------
# Test: Machine Learning Benchmark
# ---------------------------------------------------------------------------
class TestBenchmark:

    def test_evaluate_models(self, synthetic_df, detected_data):
        from pipeline.benchmark import evaluate_isolation_forest, train_and_evaluate_supervised_rf

        iso_res = evaluate_isolation_forest(detected_data)
        assert "accuracy" in iso_res
        assert "confusion_matrix" in iso_res
        assert "precision" in iso_res

        rf_res = train_and_evaluate_supervised_rf(detected_data)
        assert "accuracy" in rf_res
        assert "confusion_matrix" in rf_res
        assert len(rf_res["top_features"]) > 0
