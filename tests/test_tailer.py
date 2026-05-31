"""Tests for the alert tailer."""

import json
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.tailer import AlertTailer


@pytest.fixture
def setup_tailer():
    """Create a tailer with mocked client and a temp alert file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        alerts_dir = Path(tmpdir) / "logs"
        alerts_dir.mkdir()
        state_dir = Path(tmpdir) / "state"
        state_dir.mkdir()

        # Generate a signing key
        from agent.crypto import generate_device_keypair, load_signing_key
        key_path = Path(tmpdir) / "key"
        generate_device_keypair(key_path)
        signing_key = load_signing_key(key_path)

        client = MagicMock()
        client.get_encryption_keys.return_value = [
            {"user_id": 1, "public_key": "", "key_type": "regular"}
        ]

        tailer = AlertTailer(
            client=client,
            signing_key=signing_key,
            alerts_dir=alerts_dir,
            alerts_filename="alerts.json",
            state_dir=state_dir,
        )

        yield tailer, client, alerts_dir


class TestAlertFileDetection:
    def test_no_file_returns_zero(self, setup_tailer):
        tailer, _, _ = setup_tailer
        assert tailer.poll() == 0

    def test_finds_exact_filename(self, setup_tailer):
        tailer, client, alerts_dir = setup_tailer

        # Create an alert file with no content
        (alerts_dir / "alerts.json").write_text("")
        assert tailer.poll() == 0

    def test_finds_date_suffixed_file(self, setup_tailer):
        tailer, client, alerts_dir = setup_tailer

        (alerts_dir / "alerts.json.2026-01-01").write_text("")
        assert tailer.poll() == 0

    def test_chooses_newest_file_by_mtime(self, setup_tailer):
        tailer, client, alerts_dir = setup_tailer

        older = alerts_dir / "alerts.json.2026-01-01"
        newer = alerts_dir / "alerts.json.2026-02-01"
        older.write_text("")
        newer.write_text("")

        # Ensure the newer file has a later modification timestamp.
        time.sleep(0.01)
        newer.write_text("")

        assert tailer.poll() == 0
        assert tailer._current_file == newer


class TestAlertProcessing:
    def test_processes_new_lines(self, setup_tailer):
        tailer, client, alerts_dir = setup_tailer

        # Need real AGE keys for encryption
        from ssage import SSAGE
        priv = SSAGE.generate_private_key()
        s = SSAGE(priv)
        client.get_encryption_keys.return_value = [
            {"user_id": 1, "public_key": s.public_key, "key_type": "regular"}
        ]

        alert = {
            "@timestamp": "2026-01-01T12:00:00Z",
            "event.kind": "alert",
            "rule.name": "Test Rule",
        }
        alert_line = json.dumps(alert)
        (alerts_dir / "alerts.json").write_text(alert_line + "\n")

        processed = tailer.poll()
        assert processed == 1
        client.submit_log.assert_called_once()

        # Verify the submission
        call_kwargs = client.submit_log.call_args.kwargs
        assert call_kwargs["signature"] is not None
        assert call_kwargs["content"].startswith("-----BEGIN AGE ENCRYPTED FILE-----")

        # Decrypt and verify
        decrypted = s.decrypt(call_kwargs["content"])
        assert decrypted == alert_line

    def test_skips_already_processed_lines(self, setup_tailer):
        tailer, client, alerts_dir = setup_tailer

        from ssage import SSAGE
        priv = SSAGE.generate_private_key()
        s = SSAGE(priv)
        client.get_encryption_keys.return_value = [
            {"user_id": 1, "public_key": s.public_key, "key_type": "regular"}
        ]

        alert = json.dumps({"@timestamp": "2026-01-01T12:00:00Z", "rule.name": "Test"})
        (alerts_dir / "alerts.json").write_text(alert + "\n")

        tailer.poll()
        client.submit_log.reset_mock()

        # Poll again — no new lines
        assert tailer.poll() == 0
        client.submit_log.assert_not_called()

    def test_skips_duplicate_alert_lines(self, setup_tailer):
        tailer, client, alerts_dir = setup_tailer

        from ssage import SSAGE
        priv = SSAGE.generate_private_key()
        s = SSAGE(priv)
        client.get_encryption_keys.return_value = [
            {"user_id": 1, "public_key": s.public_key, "key_type": "regular"}
        ]

        alert = json.dumps({"@timestamp": "2026-01-01T12:00:00Z", "rule.name": "Test"})
        duplicate = json.dumps({"rule.name": "Test", "@timestamp": "2026-01-01T12:00:00Z"})
        (alerts_dir / "alerts.json").write_text(alert + "\n" + duplicate + "\n")

        processed = tailer.poll()
        assert processed == 1
        client.submit_log.assert_called_once()

    def test_persists_sent_hashes_across_restart(self, setup_tailer):
        tailer, client, alerts_dir = setup_tailer

        from ssage import SSAGE
        priv = SSAGE.generate_private_key()
        s = SSAGE(priv)
        client.get_encryption_keys.return_value = [
            {"user_id": 1, "public_key": s.public_key, "key_type": "regular"}
        ]

        alert_line = json.dumps({"@timestamp": "2026-01-01T12:00:00Z", "rule.name": "Test"})
        (alerts_dir / "alerts.json").write_text(alert_line + "\n")
        tailer.poll()

        # Restart tailer and append the same alert line again
        tailer2 = AlertTailer(
            client=client,
            signing_key=tailer._signing_key,
            alerts_dir=alerts_dir,
            alerts_filename="alerts.json",
            state_dir=tailer._state_dir,
        )
        client.submit_log.reset_mock()

        with open(alerts_dir / "alerts.json", "a") as f:
            f.write(alert_line + "\n")

        assert tailer2.poll() == 0
        client.submit_log.assert_not_called()

    def test_processes_appended_lines(self, setup_tailer):
        tailer, client, alerts_dir = setup_tailer

        from ssage import SSAGE
        priv = SSAGE.generate_private_key()
        s = SSAGE(priv)
        client.get_encryption_keys.return_value = [
            {"user_id": 1, "public_key": s.public_key, "key_type": "regular"}
        ]

        alert_file = alerts_dir / "alerts.json"
        alert1 = json.dumps({"@timestamp": "2026-01-01T12:00:00Z", "rule.name": "First"})
        alert_file.write_text(alert1 + "\n")

        tailer.poll()
        client.submit_log.reset_mock()

        # Append a new line
        with open(alert_file, "a") as f:
            alert2 = json.dumps({"@timestamp": "2026-01-01T12:01:00Z", "rule.name": "Second"})
            f.write(alert2 + "\n")

        processed = tailer.poll()
        assert processed == 1


class TestOffsetPersistence:
    def test_saves_and_loads_offset(self, setup_tailer):
        tailer, client, alerts_dir = setup_tailer

        from ssage import SSAGE
        priv = SSAGE.generate_private_key()
        s = SSAGE(priv)
        client.get_encryption_keys.return_value = [
            {"user_id": 1, "public_key": s.public_key, "key_type": "regular"}
        ]

        alert = json.dumps({"@timestamp": "2026-01-01T12:00:00Z", "rule.name": "Test"})
        (alerts_dir / "alerts.json").write_text(alert + "\n")
        tailer.poll()

        # Create a new tailer instance — should resume from saved offset
        tailer2 = AlertTailer(
            client=client,
            signing_key=tailer._signing_key,
            alerts_dir=alerts_dir,
            alerts_filename="alerts.json",
            state_dir=tailer._state_dir,
        )
        client.submit_log.reset_mock()
        assert tailer2.poll() == 0


class TestNoEncryptionKeys:
    def test_skips_when_no_keys(self, setup_tailer):
        tailer, client, alerts_dir = setup_tailer

        client.get_encryption_keys.return_value = []

        alert = json.dumps({"@timestamp": "2026-01-01T12:00:00Z", "rule.name": "Test"})
        (alerts_dir / "alerts.json").write_text(alert + "\n")

        processed = tailer.poll()
        assert processed == 0
        client.submit_log.assert_not_called()
