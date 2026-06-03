"""Tail radegast's alerts NDJSON file and forward encrypted entries to the backend."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.client import BackendClient
from agent.crypto import encrypt_for_recipients, sign_message

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
        log_severity: bool = True,
    ):
        self._client = client
        self._signing_key = signing_key
        self._alerts_dir = alerts_dir
        self._alerts_filename = alerts_filename
        self._state_dir = state_dir
        self._log_severity = log_severity
        self._offset_path = state_dir / "tail_offset.json"
        self._sent_hashes_path = state_dir / "sent_alert_hashes.json"
        self._encryption_keys: list[str] = []
        self._keys_last_fetched: float = 0
        self._current_file: Path | None = None
        self._current_inode: int | None = None
        self._offset: int = 0
        self._sent_hashes: deque[str] = deque(maxlen=5000)
        self._sent_hashes_set: set[str] = set()
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
        candidates.extend(
            p for p in self._alerts_dir.glob(pattern) if p.is_file()
        )

        if not candidates:
            return None

        return max(candidates, key=lambda path: path.stat().st_mtime)

    def _refresh_keys(self) -> None:
        """Fetch encryption keys from the backend if stale."""
        now = time.time()
        if now - self._keys_last_fetched < KEYS_REFRESH_INTERVAL and self._encryption_keys:
            return

        try:
            keys_data = self._client.get_encryption_keys()
            self._encryption_keys = [k["public_key"] for k in keys_data]
            self._keys_last_fetched = now
            if self._encryption_keys:
                logger.debug("Refreshed encryption keys: %d recipient(s)", len(self._encryption_keys))
            else:
                logger.warning("No encryption keys available — logs will not be forwarded")
        except Exception as e:
            logger.error("Failed to refresh encryption keys: %s", e)

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

        # Parse to extract timestamp and optional severity
        severity = None
        try:
            alert = json.loads(line)
            timestamp_str = alert.get("@timestamp")
            if timestamp_str:
                alert_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            else:
                alert_time = datetime.now(timezone.utc)
            if self._log_severity:
                severity = alert.get("severity")
                if severity is None:
                    event_severity = alert.get("event.severity")
                    if event_severity is None and isinstance(alert.get("event"), dict):
                        event_severity = alert["event"].get("severity")
                    if event_severity is not None:
                        try:
                            val = float(event_severity)
                            levels = [(0, "informational"), (21, "low"), (47, "medium"), (73, "high"), (99, "critical")]
                            severity = min(levels, key=lambda pair: abs(val - pair[0]))[1]
                        except (ValueError, TypeError):
                            pass
        except (json.JSONDecodeError, ValueError):
            alert_time = datetime.now(timezone.utc)

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
        )

        self._append_sent_hash(alert_hash)
        return True
