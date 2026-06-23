"""Tail radegast's alerts NDJSON file and forward encrypted entries to the backend."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import zipfile
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from radegast_edr_agent.client import BackendClient
from radegast_edr_agent.crypto import encrypt_for_recipients, sign_message
from radegast_edr_agent.exclusions import ExclusionManager

logger = logging.getLogger(__name__)

KEYS_REFRESH_INTERVAL = 60  # seconds between refreshing encryption keys


class AlertTailer:
    """Tails radegast alert files and submits encrypted log entries."""

    def __init__(
        self,
        client: BackendClient,
        signing_key: Ed25519PrivateKey,
        alerts_dir: Path,
        alerts_filename: str,
        state_dir: Path,
        send_severity: bool = True,
        send_rule_id: bool = True,
        enable_exclusions: bool = True,
        send_excluded_by: bool = True,
    ):
        self._client = client
        self._signing_key = signing_key
        self._alerts_dir = alerts_dir
        self._alerts_filename = alerts_filename
        self._state_dir = state_dir
        self._send_severity = send_severity
        self._send_rule_id = send_rule_id
        self._enable_exclusions = enable_exclusions
        self._send_excluded_by = send_excluded_by
        self._offset_path = state_dir / "tail_offset.json"
        self._sent_hashes_path = state_dir / "sent_alert_hashes.json"
        self._encryption_keys: list[str] = []
        self._keys_last_fetched: float = 0
        self._current_file: Path | None = None
        self._current_inode: int | None = None
        self._offset: int = 0
        self._sent_hashes: deque[str] = deque(maxlen=5000)
        self._sent_hashes_set: set[str] = set()

        # Initialize exclusion manager if enabled
        if enable_exclusions:
            self._exclusion_manager = ExclusionManager(client, state_dir)
        else:
            self._exclusion_manager = None

        self._load_offset()
        self._load_sent_hashes()

    def _load_offset(self) -> None:
        """Restore tail position from disk."""
        if self._offset_path.exists():
            data = json.loads(self._offset_path.read_text())
            self._offset = data.get("offset", 0)
            saved_file = data.get("file")
            if saved_file:
                self._current_file = Path(saved_file)
                if self._current_file.exists():
                    self._current_inode = os.stat(self._current_file).st_ino

    def _save_offset(self) -> None:
        """Persist tail position to disk."""
        self._state_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "file": str(self._current_file) if self._current_file else None,
            "offset": self._offset,
        }
        self._offset_path.write_text(json.dumps(data))

    def _load_sent_hashes(self) -> None:
        """Restore recently sent alert hashes from disk."""
        if self._sent_hashes_path.exists():
            try:
                data = json.loads(self._sent_hashes_path.read_text())
                if isinstance(data, list):
                    for value in data:
                        if isinstance(value, str):
                            self._sent_hashes.append(value)
                    self._sent_hashes_set = set(self._sent_hashes)
            except json.JSONDecodeError:
                logger.warning("Failed to parse sent alert hash state, starting fresh")

    def _save_sent_hashes(self) -> None:
        """Persist recently sent alert hashes to disk."""
        self._state_dir.mkdir(parents=True, exist_ok=True)
        self._sent_hashes_path.write_text(json.dumps(list(self._sent_hashes)))

    def _hash_alert_line(self, line: str) -> str:
        try:
            alert = json.loads(line)
            normalized = json.dumps(alert, sort_keys=True, separators=(",", ":"))
        except json.JSONDecodeError:
            normalized = line
        return hashlib.md5(normalized.encode("utf-8")).hexdigest()

    def _append_sent_hash(self, alert_hash: str) -> None:
        if alert_hash in self._sent_hashes_set:
            return
        if len(self._sent_hashes) == self._sent_hashes.maxlen:
            oldest = self._sent_hashes[0]
            self._sent_hashes_set.discard(oldest)
        self._sent_hashes.append(alert_hash)
        self._sent_hashes_set.add(alert_hash)
        self._save_sent_hashes()

    def _find_alert_file(self) -> Path | None:
        """Find the current alert file by newest modification time."""
        candidates = []

        exact = self._alerts_dir / self._alerts_filename
        if exact.exists() and exact.is_file():
            candidates.append(exact)

        pattern = f"{self._alerts_filename}.*"
        candidates.extend(p for p in self._alerts_dir.glob(pattern) if p.is_file())

        if not candidates:
            return None

        return max(candidates, key=lambda path: path.stat().st_mtime)

    def _refresh_keys(self) -> None:
        """Fetch encryption keys from the backend if stale."""
        now = time.time()
        if now - self._keys_last_fetched < KEYS_REFRESH_INTERVAL and self._encryption_keys:
            pass  # Will still refresh exclusions if needed
        else:
            try:
                keys_data = self._client.get_encryption_keys()
                self._encryption_keys = [k["public_key"] for k in keys_data]
                self._keys_last_fetched = now
                if self._encryption_keys:
                    logger.debug(
                        "Refreshed encryption keys: %d recipient(s)",
                        len(self._encryption_keys),
                    )
                else:
                    logger.warning("No encryption keys available — logs will not be forwarded")
            except Exception as e:
                logger.error("Failed to refresh encryption keys: %s", e)

        # Always refresh exclusions (it has its own interval)
        if self._exclusion_manager:
            self._exclusion_manager.refresh()

    def force_refresh_exclusions(self) -> None:
        """Force an immediate exclusion refresh, bypassing the rate-limit interval.

        Call this whenever packs are synced so exclusions stay in lock-step
        with the rest of the device-group configuration.
        """
        if self._exclusion_manager:
            self._exclusion_manager._last_fetched = 0
            self._exclusion_manager.refresh()

    def poll(self) -> int:
        """Poll for new alert lines and submit them. Returns number of lines processed."""
        alert_file = self._find_alert_file()
        if alert_file is None:
            return 0

        # Detect file rotation (inode change or new file)
        current_inode = os.stat(alert_file).st_ino
        if self._current_file != alert_file or self._current_inode != current_inode:
            if self._current_file and self._current_file != alert_file:
                logger.info("Alert file rotated: %s → %s", self._current_file, alert_file)
            self._current_file = alert_file
            self._current_inode = current_inode
            self._offset = 0

        # Read new lines from offset
        file_size = alert_file.stat().st_size
        if file_size <= self._offset:
            # File may have been truncated
            if file_size < self._offset:
                logger.info("Alert file truncated, resetting offset")
                self._offset = 0
            return 0

        self._refresh_keys()
        if not self._encryption_keys:
            return 0

        processed = 0
        initial_offset = self._offset
        with open(alert_file, "r") as f:
            f.seek(self._offset)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    if self._process_alert(line):
                        processed += 1
                except Exception as e:
                    logger.error("Failed to process alert line: %s", e)

            self._offset = f.tell()

        if self._offset != initial_offset:
            self._save_offset()

        if processed:
            logger.info("Forwarded %d alert(s)", processed)

        return processed

    def _process_alert(self, line: str) -> bool:
        """Encrypt, sign, submit a single alert line and return whether it was sent."""
        alert_hash = self._hash_alert_line(line)
        if alert_hash in self._sent_hashes_set:
            logger.debug("Skipping duplicate alert line")
            return False

        # Parse to extract timestamp, optional severity, and optional rule info
        severity = None
        rule_id = None
        rule_type = None
        alert = None
        try:
            alert = json.loads(line)
            timestamp_str = alert.get("@timestamp")
            if timestamp_str:
                alert_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            else:
                alert_time = datetime.now(timezone.utc)
            if self._send_severity:
                severity = alert.get("severity")
                if severity is None:
                    event_severity = alert.get("event.severity")
                    if event_severity is None and isinstance(alert.get("event"), dict):
                        event_severity = alert["event"].get("severity")
                    if event_severity is not None:
                        try:
                            val = float(event_severity)
                            levels = [
                                (0, "informational"),
                                (21, "low"),
                                (47, "medium"),
                                (73, "high"),
                                (99, "critical"),
                            ]
                            severity = min(levels, key=lambda pair: abs(val - pair[0]))[1]
                        except (ValueError, TypeError):
                            pass
            if self._send_rule_id:
                raw_rule_id = alert.get("rule.id")
                if raw_rule_id and isinstance(raw_rule_id, str) and "::" in raw_rule_id:
                    parts = raw_rule_id.split("::", 1)
                    rule_type = parts[0]
                    rule_id = parts[1]
        except (json.JSONDecodeError, ValueError):
            alert_time = datetime.now(timezone.utc)

        # Check if this alert should be excluded
        excluded_by = None
        if self._exclusion_manager and alert is not None:
            exc_type, exc_id = self._exclusion_manager.check_exclusion(alert)
            if exc_type == "hard":
                logger.info("Alert excluded by hard exclusion rule, not forwarding")
                return False
            elif exc_type == "soft":
                logger.info("Alert matched soft exclusion, sending with informational severity")
                severity = "informational"
                if self._send_excluded_by:
                    excluded_by = exc_id

        # Encrypt the alert content for all recipients
        encrypted = encrypt_for_recipients(line, self._encryption_keys)

        # Sign the original plaintext
        signature = sign_message(line.encode(), self._signing_key)

        # Submit to backend
        self._client.submit_log(
            time=alert_time,
            content=encrypted,
            signature=signature,
            severity=severity,
            rule_id=rule_id,
            rule_type=rule_type,
            excluded_by=excluded_by,
        )

        self._append_sent_hash(alert_hash)
        return True


def rotate_rustinel_logs(log_dir: Path, max_size_mb: int, max_age_days: int) -> None:
    """Rotate active log/json files and clean up old zip files based on age."""
    if not log_dir.exists() or not log_dir.is_dir():
        return

    # 1. Rotate large files
    max_size_bytes = max_size_mb * 1024 * 1024
    for file_path in log_dir.iterdir():
        if not file_path.is_file():
            continue
        # Only rotate active log/json files
        if file_path.suffix not in (".log", ".json"):
            continue

        try:
            if file_path.stat().st_size > max_size_bytes:
                # Find next index
                idx = 1
                while True:
                    zip_path = log_dir / f"{file_path.name}.{idx}.zip"
                    if not zip_path.exists():
                        break
                    idx += 1

                # Move atomically and recreate empty file
                temp_path = log_dir / f"{file_path.name}.tmp"
                os.replace(file_path, temp_path)
                file_path.touch()

                # Create zip archive with max compression
                with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zipf:
                    zipf.write(temp_path, arcname=file_path.name)

                temp_path.unlink()
                logger.info("Rotated log file %s to %s", file_path.name, zip_path.name)
        except Exception as e:
            logger.error("Failed to rotate file %s: %s", file_path.name, e)

    # 2. Clean up old archives
    max_age_seconds = max_age_days * 24 * 3600
    now = time.time()
    for file_path in log_dir.iterdir():
        if not file_path.is_file():
            continue
        if file_path.suffix == ".zip":
            try:
                age_seconds = now - file_path.stat().st_mtime
                if age_seconds > max_age_seconds:
                    file_path.unlink()
                    logger.info(
                        "Deleted expired log archive %s (age > %d days)",
                        file_path.name,
                        max_age_days,
                    )
            except Exception as e:
                logger.error("Failed to delete expired log archive %s: %s", file_path.name, e)
