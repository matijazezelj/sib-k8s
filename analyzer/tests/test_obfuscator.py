"""Tests for the analyzer obfuscator module."""

import pytest
import sys
import os

# Allow running tests from the analyzer/ directory without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.config import ObfuscationLevel
from src.obfuscator import Obfuscator


# ---------------------------------------------------------------------------
# Secret redaction (all levels)
# ---------------------------------------------------------------------------

class TestSecretRedaction:
    def test_aws_access_key_redacted(self):
        o = Obfuscator(ObfuscationLevel.MINIMAL)
        result = o._obfuscate_secrets("key=AKIAIOSFODNN7EXAMPLE found")
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[REDACTED-AWS-KEY]" in result

    def test_github_pat_redacted(self):
        o = Obfuscator(ObfuscationLevel.MINIMAL)
        token = "ghp_" + "A" * 36
        result = o._obfuscate_secrets(f"token={token}")
        assert token not in result
        assert "REDACTED" in result

    def test_password_field_redacted(self):
        o = Obfuscator(ObfuscationLevel.MINIMAL)
        result = o._obfuscate_secrets("password=supersecret123")
        assert "supersecret123" not in result
        assert "REDACTED" in result

    def test_jwt_redacted(self):
        o = Obfuscator(ObfuscationLevel.MINIMAL)
        result = o._obfuscate_secrets("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig")
        assert "eyJhbGciOiJIUzI1NiJ9" not in result

    def test_gcp_service_account_redacted(self):
        o = Obfuscator(ObfuscationLevel.MINIMAL)
        result = o._obfuscate_secrets("sa=my-sa@my-project.iam.gserviceaccount.com")
        assert "my-project.iam.gserviceaccount.com" not in result
        assert "REDACTED" in result

    def test_postgres_uri_redacted(self):
        o = Obfuscator(ObfuscationLevel.MINIMAL)
        result = o._obfuscate_secrets("conn=postgres://user:hunter2@db.internal/mydb")
        assert "hunter2" not in result
        assert "REDACTED" in result

    def test_slack_webhook_redacted(self):
        o = Obfuscator(ObfuscationLevel.MINIMAL)
        # Constructed to avoid triggering VCS secret scanners on the literal string
        url = "https://hooks.slack.com/services/" + "TABCDEFGH1/BABCDEFGH1/abcdefghijklmnopqrstuvwx"
        result = o._obfuscate_secrets(url)
        assert url not in result
        assert "REDACTED" in result

    def test_secrets_applied_at_minimal_level(self):
        """Secret redaction runs at all obfuscation levels."""
        for level in ObfuscationLevel:
            o = Obfuscator(level)
            result = o.obfuscate_text("AKIAIOSFODNN7EXAMPLE leaked")
            assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_npm_token_redacted(self):
        o = Obfuscator(ObfuscationLevel.MINIMAL)
        token = "npm_" + "A" * 36
        result = o._obfuscate_secrets(f"npm_token={token}")
        assert token not in result

    def test_no_false_positive_on_plain_text(self):
        o = Obfuscator(ObfuscationLevel.MINIMAL)
        text = "Falco rule triggered: write below root dir"
        result = o._obfuscate_secrets(text)
        assert result == text


# ---------------------------------------------------------------------------
# IP obfuscation (standard+)
# ---------------------------------------------------------------------------

class TestIPObfuscation:
    def test_ipv4_replaced_at_standard(self):
        o = Obfuscator(ObfuscationLevel.STANDARD)
        result = o.obfuscate_text("Connection from 8.8.8.8")
        assert "8.8.8.8" not in result
        assert "ip-" in result

    def test_ipv4_preserved_at_minimal(self):
        o = Obfuscator(ObfuscationLevel.MINIMAL)
        result = o.obfuscate_text("Connection from 8.8.8.8")
        assert "8.8.8.8" in result

    def test_same_ip_same_hash(self):
        o = Obfuscator(ObfuscationLevel.STANDARD)
        result = o.obfuscate_text("from 10.0.0.1 to 10.0.0.1")
        # Both occurrences should hash to the same value
        tokens = [t for t in result.split() if t.startswith("ip-")]
        assert len(tokens) == 2
        assert tokens[0] == tokens[1]

    def test_different_ips_different_hashes(self):
        o = Obfuscator(ObfuscationLevel.STANDARD)
        result = o.obfuscate_text("from 10.0.0.1 to 10.0.0.2")
        tokens = [t for t in result.split() if t.startswith("ip-")]
        assert len(tokens) == 2
        assert tokens[0] != tokens[1]


# ---------------------------------------------------------------------------
# Email obfuscation (standard+)
# ---------------------------------------------------------------------------

class TestEmailObfuscation:
    def test_email_replaced_at_standard(self):
        o = Obfuscator(ObfuscationLevel.STANDARD)
        result = o.obfuscate_text("user admin@company.com logged in")
        assert "admin@company.com" not in result
        assert "redacted.local" in result

    def test_email_preserved_at_minimal(self):
        o = Obfuscator(ObfuscationLevel.MINIMAL)
        result = o.obfuscate_text("user admin@company.com logged in")
        assert "admin@company.com" in result

    def test_same_email_consistent_hash(self):
        o = Obfuscator(ObfuscationLevel.STANDARD)
        result = o.obfuscate_text("admin@acme.com and admin@acme.com")
        tokens = [t for t in result.split() if "redacted.local" in t]
        assert len(tokens) == 2
        assert tokens[0] == tokens[1]


# ---------------------------------------------------------------------------
# AWS ARN obfuscation (standard+)
# ---------------------------------------------------------------------------

class TestARNObfuscation:
    def test_arn_account_id_hashed(self):
        o = Obfuscator(ObfuscationLevel.STANDARD)
        result = o.obfuscate_text("role=arn:aws:iam::123456789012:role/my-role")
        assert "123456789012" not in result

    def test_arn_structure_preserved(self):
        o = Obfuscator(ObfuscationLevel.STANDARD)
        result = o.obfuscate_text("arn:aws:iam::123456789012:role/my-role")
        assert "arn:aws:iam::" in result


# ---------------------------------------------------------------------------
# Kubernetes-specific obfuscation (paranoid)
# ---------------------------------------------------------------------------

class TestKubernetesObfuscation:
    def test_namespace_hashed_at_paranoid(self):
        o = Obfuscator(ObfuscationLevel.PARANOID)
        result = o.obfuscate_text("namespace=production accessed")
        assert "production" not in result

    def test_system_namespace_preserved(self):
        o = Obfuscator(ObfuscationLevel.PARANOID)
        result = o.obfuscate_text("namespace=kube-system accessed")
        assert "kube-system" in result

    def test_pod_name_hashed_at_paranoid(self):
        o = Obfuscator(ObfuscationLevel.PARANOID)
        result = o.obfuscate_text("pod=my-app-6d4b8c9f7-xk2pq started")
        assert "my-app-6d4b8c9f7-xk2pq" not in result

    def test_namespace_preserved_at_standard(self):
        o = Obfuscator(ObfuscationLevel.STANDARD)
        result = o.obfuscate_text("namespace=production accessed")
        assert "production" in result


# ---------------------------------------------------------------------------
# obfuscate_alert (dict interface)
# ---------------------------------------------------------------------------

class TestObfuscateAlert:
    def test_output_field_obfuscated(self):
        alert = {
            "output": "user=attacker read /etc/shadow from 10.0.0.1",
            "rule": "Read sensitive file",
        }
        o = Obfuscator(ObfuscationLevel.STANDARD)
        result = o.obfuscate_alert(alert)
        assert "10.0.0.1" not in result["output"]
        assert result["rule"] == "Read sensitive file"

    def test_nested_output_fields_obfuscated(self):
        alert = {
            "output": "alert",
            "output_fields": {
                "proc.name": "bash",
                "fd.rip": "8.8.8.8",
            },
        }
        o = Obfuscator(ObfuscationLevel.STANDARD)
        result = o.obfuscate_alert(alert)
        assert "8.8.8.8" not in result["output_fields"]["fd.rip"]
        assert result["output_fields"]["proc.name"] == "bash"

    def test_original_alert_not_mutated(self):
        alert = {"output": "from 8.8.8.8", "rule": "test"}
        original_output = alert["output"]
        o = Obfuscator(ObfuscationLevel.STANDARD)
        o.obfuscate_alert(alert)
        assert alert["output"] == original_output

    def test_aws_secret_in_alert_redacted(self):
        alert = {"output": "AKIAIOSFODNN7EXAMPLE found in pod env", "rule": "Leaked Credential"}
        o = Obfuscator(ObfuscationLevel.MINIMAL)
        result = o.obfuscate_alert(alert)
        assert "AKIAIOSFODNN7EXAMPLE" not in result["output"]


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_string(self):
        o = Obfuscator(ObfuscationLevel.STANDARD)
        assert o.obfuscate_text("") == ""

    def test_no_sensitive_data_unchanged(self):
        o = Obfuscator(ObfuscationLevel.STANDARD)
        text = "Falco rule triggered: write below root dir"
        assert o.obfuscate_text(text) == text

    def test_obfuscate_dict_list_values(self):
        o = Obfuscator(ObfuscationLevel.STANDARD)
        data = {"tags": ["8.8.8.8", "normal-tag"]}
        result = o.obfuscate_dict(data)
        assert "8.8.8.8" not in result["tags"][0]
        assert result["tags"][1] == "normal-tag"
