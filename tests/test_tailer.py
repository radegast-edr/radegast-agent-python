"""Tests for the alert tailer."""

import json
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from radegast_edr_agent.tailer import AlertTailer


@pytest.fixture
def setup_tailer():
    """Create a tailer with mocked client and a temp alert file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        alerts_dir = Path(tmpdir) / "logs"
        alerts_dir.mkdir()
        state_dir = Path(tmpdir) / "state"
        state_dir.mkdir()

        # Generate a signing key
        from radegast_edr_agent.crypto import generate_device_keypair, load_signing_key
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


class TestLogSeverity:
    def test_parses_severity_when_enabled(self, setup_tailer):
        tailer, client, alerts_dir = setup_tailer
        tailer._log_severity = True

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
            "severity": "high",
        }
        alert_line = json.dumps(alert)
        (alerts_dir / "alerts.json").write_text(alert_line + "\n")

        processed = tailer.poll()
        assert processed == 1
        client.submit_log.assert_called_once()

        call_kwargs = client.submit_log.call_args.kwargs
        assert call_kwargs["severity"] == "high"

    def test_ignores_severity_when_disabled(self, setup_tailer):
        tailer, client, alerts_dir = setup_tailer
        tailer._log_severity = False

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
            "severity": "high",
        }
        alert_line = json.dumps(alert)
        (alerts_dir / "alerts.json").write_text(alert_line + "\n")

        processed = tailer.poll()
        assert processed == 1
        client.submit_log.assert_called_once()

        call_kwargs = client.submit_log.call_args.kwargs
        assert call_kwargs.get("severity") is None

    def test_falls_back_to_event_severity_flat(self, setup_tailer):
        tailer, client, alerts_dir = setup_tailer
        tailer._log_severity = True

        from ssage import SSAGE
        priv = SSAGE.generate_private_key()
        s = SSAGE(priv)
        client.get_encryption_keys.return_value = [
            {"user_id": 1, "public_key": s.public_key, "key_type": "regular"}
        ]

        # Case 1: event.severity is 25 (closest to 21 -> "low")
        alert = {
            "@timestamp": "2026-01-01T12:00:00Z",
            "event.kind": "alert",
            "rule.name": "Test Rule",
            "event.severity": 25,
        }
        (alerts_dir / "alerts.json").write_text(json.dumps(alert) + "\n")
        assert tailer.poll() == 1
        client.submit_log.assert_called_once()
        assert client.submit_log.call_args.kwargs["severity"] == "low"

        # Case 2: event.severity is 80 (closest to 73 -> "high")
        client.submit_log.reset_mock()
        alert2 = {
            "@timestamp": "2026-01-01T12:00:00Z",
            "event.kind": "alert",
            "rule.name": "Test Rule 2",
            "event.severity": "80",
        }
        with open(alerts_dir / "alerts.json", "a") as f:
            f.write(json.dumps(alert2) + "\n")
        assert tailer.poll() == 1
        client.submit_log.assert_called_once()
        assert client.submit_log.call_args.kwargs["severity"] == "high"

    def test_falls_back_to_event_severity_nested(self, setup_tailer):
        tailer, client, alerts_dir = setup_tailer
        tailer._log_severity = True

        from ssage import SSAGE
        priv = SSAGE.generate_private_key()
        s = SSAGE(priv)
        client.get_encryption_keys.return_value = [
            {"user_id": 1, "public_key": s.public_key, "key_type": "regular"}
        ]

        alert = {
            "@timestamp": "2026-01-01T12:00:00Z",
            "event": {
                "severity": 99
            }
        }
        (alerts_dir / "alerts.json").write_text(json.dumps(alert) + "\n")
        assert tailer.poll() == 1
        assert client.submit_log.call_args.kwargs["severity"] == "critical"

    def test_severity_takes_precedence_over_event_severity(self, setup_tailer):
        tailer, client, alerts_dir = setup_tailer
        tailer._log_severity = True

        from ssage import SSAGE
        priv = SSAGE.generate_private_key()
        s = SSAGE(priv)
        client.get_encryption_keys.return_value = [
            {"user_id": 1, "public_key": s.public_key, "key_type": "regular"}
        ]

        alert = {
            "@timestamp": "2026-01-01T12:00:00Z",
            "severity": "medium",
            "event.severity": 99,
        }
        (alerts_dir / "alerts.json").write_text(json.dumps(alert) + "\n")
        assert tailer.poll() == 1
        assert client.submit_log.call_args.kwargs["severity"] == "medium"


class TestExclusionBehavior:
    """Tests for exclusion filtering and force-refresh wiring."""

    def _make_tailer_with_exclusions(self, setup_tailer, exclusions):
        tailer, client, alerts_dir = setup_tailer
        # Inject exclusions directly so we don't need the jsonata library at test time
        tailer._exclusion_manager._exclusions = exclusions
        tailer._exclusion_manager._last_fetched = time.time()  # prevent network call
        return tailer, client, alerts_dir

    def test_excluded_alert_is_not_forwarded(self, setup_tailer):
        """An alert that matches an exclusion must be dropped, not submitted."""
        exclusions = [{"id": 1, "name": "Drop test", "jsonata_query": "some_query"}]
        tailer, client, alerts_dir = self._make_tailer_with_exclusions(setup_tailer, exclusions)

        from ssage import SSAGE
        priv = SSAGE.generate_private_key()
        client.get_encryption_keys.return_value = [
            {"user_id": 1, "public_key": SSAGE(priv).public_key, "key_type": "regular"}
        ]

        alert = {"@timestamp": "2026-01-01T12:00:00Z", "rule.name": "Test"}
        (alerts_dir / "alerts.json").write_text(json.dumps(alert) + "\n")

        # Patch is_excluded to return True without needing jsonata
        tailer._exclusion_manager.is_excluded = MagicMock(return_value=True)
        processed = tailer.poll()

        assert processed == 0
        client.submit_log.assert_not_called()

    def test_non_excluded_alert_is_forwarded(self, setup_tailer):
        """An alert that does NOT match any exclusion must be submitted normally."""
        tailer, client, alerts_dir = self._make_tailer_with_exclusions(setup_tailer, [])

        from ssage import SSAGE
        priv = SSAGE.generate_private_key()
        client.get_encryption_keys.return_value = [
            {"user_id": 1, "public_key": SSAGE(priv).public_key, "key_type": "regular"}
        ]

        alert = {"@timestamp": "2026-01-01T12:00:00Z", "rule.name": "Test"}
        (alerts_dir / "alerts.json").write_text(json.dumps(alert) + "\n")

        tailer._exclusion_manager.is_excluded = MagicMock(return_value=False)
        processed = tailer.poll()

        assert processed == 1
        client.submit_log.assert_called_once()

    def test_force_refresh_exclusions_resets_timer(self, setup_tailer):
        """force_refresh_exclusions() bypasses the rate-limit by zeroing _last_fetched."""
        tailer, client, alerts_dir = setup_tailer
        client.get_exclusions.return_value = []

        # Simulate a recent refresh so normal refresh() would be a no-op
        tailer._exclusion_manager._last_fetched = time.time()
        tailer._exclusion_manager.refresh()
        client.get_exclusions.assert_not_called()

        # force_refresh_exclusions() must always hit the backend
        tailer.force_refresh_exclusions()
        client.get_exclusions.assert_called_once()

    def test_force_refresh_exclusions_updates_list(self, setup_tailer):
        """force_refresh_exclusions() replaces in-memory exclusions with backend response."""
        tailer, client, alerts_dir = setup_tailer
        new_exclusions = [{"id": 42, "name": "New rule", "jsonata_query": "true"}]
        client.get_exclusions.return_value = new_exclusions

        tailer.force_refresh_exclusions()

        assert tailer._exclusion_manager._exclusions == new_exclusions

    def test_no_exclusion_manager_when_disabled(self, setup_tailer):
        """When enable_exclusions=False the tailer has no exclusion manager."""
        tailer, client, alerts_dir = setup_tailer
        # Patch a fresh tailer with exclusions disabled
        from radegast_edr_agent.tailer import AlertTailer
        from radegast_edr_agent.crypto import load_signing_key
        from pathlib import Path
        import tempfile, os

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "key"
            from radegast_edr_agent.crypto import generate_device_keypair
            generate_device_keypair(key_path)
            signing_key = load_signing_key(key_path)
            disabled_tailer = AlertTailer(
                client=client,
                signing_key=signing_key,
                alerts_dir=Path(tmpdir),
                alerts_filename="alerts.json",
                state_dir=Path(tmpdir),
                enable_exclusions=False,
            )
        assert disabled_tailer._exclusion_manager is None
        # force_refresh should be a no-op without crashing
        disabled_tailer.force_refresh_exclusions()
