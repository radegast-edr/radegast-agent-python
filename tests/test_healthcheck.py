"""Tests for the healthcheck mechanism."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from ssage import SSAGE

from radegast_edr_agent.crypto import generate_device_keypair, load_signing_key
from radegast_edr_agent.healthcheck import RULE_TITLE, HealthCheckManager
from radegast_edr_agent.tailer import AlertTailer


@pytest.fixture
def temp_dirs():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        rule_dir = base / "rules" / "sigma" / "_healthcheck"
        alerts_dir = base / "logs"
        state_dir = base / "state"
        rule_dir.mkdir(parents=True)
        alerts_dir.mkdir(parents=True)
        state_dir.mkdir(parents=True)
        yield base, rule_dir, alerts_dir, state_dir


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.get_encryption_keys.return_value = []
    return client


class TestHealthCheckRuleGeneration:
    def test_write_probe_rule_creates_valid_yaml(self, temp_dirs, mock_client):
        _, rule_dir, _, _ = temp_dirs
        mgr = HealthCheckManager(client=mock_client, rule_dir=rule_dir)
        probe_uuid = "12345678-1234-5678-1234-567812345678"

        rule_file = mgr.write_probe_rule(probe_uuid)
        assert rule_file.exists()
        assert rule_file.name == "healthcheck.yml"

        content = rule_file.read_text(encoding="utf-8")
        assert f"title: {RULE_TITLE}" in content
        assert f"id: {probe_uuid}" in content
        assert "category: process_creation" in content
        assert f"CommandLine|contains: '{probe_uuid}'" in content
        assert "condition: selection" in content


class TestHealthCheckProbeExecution:
    def test_execute_probe_command(self, temp_dirs, mock_client):
        _, rule_dir, _, _ = temp_dirs
        mgr = HealthCheckManager(client=mock_client, rule_dir=rule_dir)
        probe_uuid = "test-uuid-123"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            res = mgr.execute_probe_command(probe_uuid)
            assert res is True
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert probe_uuid in args


class TestHealthCheckAlertIdentification:
    def test_is_healthcheck_alert_by_rule_name(self, temp_dirs, mock_client):
        _, rule_dir, _, _ = temp_dirs
        mgr = HealthCheckManager(client=mock_client, rule_dir=rule_dir)
        alert = {"rule.name": RULE_TITLE, "rule.id": "sigma::something"}
        assert mgr.is_healthcheck_alert(alert) is True

    def test_is_healthcheck_alert_by_probe_uuid(self, temp_dirs, mock_client):
        _, rule_dir, _, _ = temp_dirs
        mgr = HealthCheckManager(client=mock_client, rule_dir=rule_dir)
        mgr._active_probe_uuid = "probe-uuid-abc"

        alert = {"rule.name": "Other Rule", "rule.id": "sigma::probe-uuid-abc"}
        assert mgr.is_healthcheck_alert(alert) is True

        alert_cmd = {"rule.name": "Other", "CommandLine": "python -c pass probe-uuid-abc"}
        assert mgr.is_healthcheck_alert(alert_cmd) is True

    def test_unrelated_alert_not_identified_as_healthcheck(self, temp_dirs, mock_client):
        _, rule_dir, _, _ = temp_dirs
        mgr = HealthCheckManager(client=mock_client, rule_dir=rule_dir)
        mgr._active_probe_uuid = "probe-uuid-abc"

        alert = {
            "rule.name": "Suspicious Download",
            "rule.id": "sigma::unrelated-rule-id",
            "CommandLine": "curl http://malware.com",
        }
        assert mgr.is_healthcheck_alert(alert) is False


class TestHealthCheckLifecycle:
    def test_run_check_when_disabled(self, temp_dirs, mock_client):
        _, rule_dir, _, _ = temp_dirs
        mgr = HealthCheckManager(client=mock_client, rule_dir=rule_dir, enabled=False)

        res = mgr.run_check(tailer=None)
        assert res is None
        mock_client.report_health.assert_called_once_with(None)

    def test_run_check_success(self, temp_dirs, mock_client):
        _, rule_dir, _, _ = temp_dirs
        mgr = HealthCheckManager(client=mock_client, rule_dir=rule_dir, timeout=2.0)

        tailer = MagicMock()

        def fake_poll():
            mgr.record_healthcheck_alert({"rule.name": RULE_TITLE})

        tailer.poll.side_effect = fake_poll

        with patch("time.sleep"):
            with patch.object(mgr, "execute_probe_command", return_value=True):
                res = mgr.run_check(tailer=tailer)

        assert res is True
        assert mgr.last_status is True
        mock_client.report_health.assert_called_once_with(True)

    def test_run_check_timeout_fails(self, temp_dirs, mock_client):
        _, rule_dir, _, _ = temp_dirs
        mgr = HealthCheckManager(client=mock_client, rule_dir=rule_dir, timeout=0.01)

        tailer = MagicMock()

        with patch("time.sleep"):
            with patch.object(mgr, "execute_probe_command", return_value=True):
                res = mgr.run_check(tailer=tailer)

        assert res is False
        assert mgr.last_status is False
        mock_client.report_health.assert_called_once_with(False)


class TestAlertTailerHealthcheckSuppression:
    def test_tailer_suppresses_healthcheck_alert_and_records(self, temp_dirs, mock_client):
        base, rule_dir, alerts_dir, state_dir = temp_dirs

        key_path = base / "signing_key"
        generate_device_keypair(key_path)
        signing_key = load_signing_key(key_path)

        priv = SSAGE.generate_private_key()
        s = SSAGE(priv)
        mock_client.get_encryption_keys.return_value = [
            {"user_id": 1, "public_key": s.public_key, "key_type": "regular"}
        ]

        mgr = HealthCheckManager(client=mock_client, rule_dir=rule_dir)
        probe_uuid = "probe-uuid-999"
        mgr._active_probe_uuid = probe_uuid

        tailer = AlertTailer(
            client=mock_client,
            signing_key=signing_key,
            alerts_dir=alerts_dir,
            alerts_filename="alerts.json",
            state_dir=state_dir,
            healthcheck_manager=mgr,
        )

        healthcheck_alert = {
            "@timestamp": "2026-01-01T12:00:00Z",
            "rule.name": RULE_TITLE,
            "rule.id": f"sigma::{probe_uuid}",
            "CommandLine": f"python3 -c pass {probe_uuid}",
        }
        normal_alert = {
            "@timestamp": "2026-01-01T12:00:01Z",
            "rule.name": "Normal Detection",
            "rule.id": "sigma::normal-rule",
        }

        alerts_file = alerts_dir / "alerts.json"
        alerts_file.write_text(json.dumps(healthcheck_alert) + "\n" + json.dumps(normal_alert) + "\n")

        processed = tailer.poll()

        # Only the normal alert should be counted as forwarded
        assert processed == 1
        assert mgr._probe_received is True

        # submit_log should only have been called once for the normal alert
        assert mock_client.submit_log.call_count == 1
        call_kwargs = mock_client.submit_log.call_args.kwargs
        decrypted = s.decrypt(call_kwargs["content"])
        assert json.loads(decrypted)["rule.name"] == "Normal Detection"


class TestHealthCheckNonBlocking:
    def test_non_blocking_lifecycle_success(self, temp_dirs, mock_client):
        _, rule_dir, _, _ = temp_dirs
        mgr = HealthCheckManager(client=mock_client, rule_dir=rule_dir, timeout=10.0)

        # 1. Start check
        mgr.start_check()
        assert mgr._state == "RELOADING"
        assert mgr._active_probe_uuid is not None

        # 2. Update before reload delay
        with patch.object(mgr, "execute_probe_command") as mock_exec:
            mgr.update()
            assert mgr._state == "RELOADING"
            mock_exec.assert_not_called()

        # 3. Simulate reload delay elapsed
        mgr._state_start_time -= 5.0
        with patch.object(mgr, "execute_probe_command") as mock_exec:
            mgr.update()
            assert mgr._state == "VERIFYING"
            mock_exec.assert_called_once_with(mgr._active_probe_uuid)

        # 4. Update while verifying (not received yet)
        mgr.update()
        assert mgr._state == "VERIFYING"

        # 5. Receive probe alert
        mgr.record_healthcheck_alert({"rule.name": RULE_TITLE})
        mgr.update()
        assert mgr._state == "IDLE"
        assert mgr.last_status is True
        mock_client.report_health.assert_called_once_with(True)

    def test_non_blocking_lifecycle_timeout(self, temp_dirs, mock_client):
        _, rule_dir, _, _ = temp_dirs
        mgr = HealthCheckManager(client=mock_client, rule_dir=rule_dir, timeout=10.0)

        # 1. Start check
        mgr.start_check()
        assert mgr._state == "RELOADING"

        # 2. Simulate reload delay elapsed
        mgr._state_start_time -= 5.0
        with patch.object(mgr, "execute_probe_command"):
            mgr.update()
            assert mgr._state == "VERIFYING"

        # 3. Simulate timeout elapsed
        mgr._state_start_time -= 10.0
        mgr.update()
        assert mgr._state == "IDLE"
        assert mgr.last_status is False
        mock_client.report_health.assert_called_once_with(False)
