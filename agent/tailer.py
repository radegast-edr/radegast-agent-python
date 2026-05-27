"""Tail radegast's alerts NDJSON file and forward encrypted entries to the backend."""

from __future__ import annotations

import json
import logging
import os
import time
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
    ):
        self._client = client
        self._signing_key = signing_key
        self._alerts_dir = alerts_dir
        self._alerts_filename = alerts_filename
        self._state_dir = state_dir
        self._offset_path = state_dir / "tail_offset.json"
        self._encryption_keys: list[str] = []
        self._keys_last_fetched: float = 0
        self._current_file: Path | None = None
        self._current_inode: int | None = None
        self._offset: int = 0
        self._load_offset()

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

    def _find_alert_file(self) -> Path | None:
        """Find the current alert file (may have date suffix)."""
        # Check for exact filename first
        exact = self._alerts_dir / self._alerts_filename
        if exact.exists():
            return exact

        # Check for date-suffixed files, return the most recent
        pattern = f"{self._alerts_filename}.*"
        candidates = sorted(self._alerts_dir.glob(pattern), reverse=True)
        return candidates[0] if candidates else None

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
        with open(alert_file, "r") as f:
            f.seek(self._offset)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    self._process_alert(line)
                    processed += 1
                except Exception as e:
                    logger.error("Failed to process alert line: %s", e)

            self._offset = f.tell()

        if processed:
            self._save_offset()
            logger.info("Forwarded %d alert(s)", processed)

        return processed

    def _process_alert(self, line: str) -> None:
        """Encrypt, sign, and submit a single alert line."""
        # Parse to extract timestamp
        try:
            alert = json.loads(line)
            timestamp_str = alert.get("@timestamp")
            if timestamp_str:
                alert_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            else:
                alert_time = datetime.now(timezone.utc)
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
        )
