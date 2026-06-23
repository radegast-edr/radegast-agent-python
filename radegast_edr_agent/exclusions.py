"""Exclusion management — downloads and applies JSONata exclusions from the backend."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from jsonata import Jsonata

from radegast_edr_agent.client import BackendClient

logger = logging.getLogger(__name__)

EXCLUSIONS_REFRESH_INTERVAL = 300  # 5 minutes between refreshing exclusions


class ExclusionManager:
    """Manages downloading JSONata exclusions and checking alerts against them."""

    def __init__(self, client: BackendClient, state_dir: Path):
        self._client = client
        self._state_dir = state_dir
        self._exclusions: list[dict[str, Any]] = []
        self._last_fetched: float = 0
        self._last_json: str | None = None

    def _load_from_disk(self) -> list[dict[str, Any]]:
        """Load exclusions from disk cache."""
        cache_path = self._state_dir / "exclusions.json"
        if cache_path.exists():
            try:
                return json.loads(cache_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return []

    def _save_to_disk(self, exclusions: list[dict[str, Any]]) -> None:
        """Save exclusions to disk cache."""
        self._state_dir.mkdir(parents=True, exist_ok=True)
        cache_path = self._state_dir / "exclusions.json"
        cache_path.write_text(json.dumps(exclusions, indent=2))

    def refresh(self) -> list[dict[str, Any]]:
        """Refresh exclusions from the backend. Returns the updated list."""
        now = time.time()
        if now - self._last_fetched < EXCLUSIONS_REFRESH_INTERVAL:
            return self._exclusions

        try:
            exclusions = self._client.get_exclusions()
            self._exclusions = exclusions
            self._last_fetched = now
            self._last_json = json.dumps(exclusions, sort_keys=True)
            self._save_to_disk(exclusions)
            logger.info("Refreshed %d exclusion(s) from backend", len(exclusions))
            return exclusions
        except Exception as e:
            logger.error("Failed to refresh exclusions: %s", e)
            # Return cached exclusions if we have them
            if self._exclusions:
                return self._exclusions
            # Try loading from disk
            disk_exclusions = self._load_from_disk()
            if disk_exclusions:
                self._exclusions = disk_exclusions
                logger.warning("Using cached exclusions from disk")
                return disk_exclusions
            return []

    def check_exclusion(self, alert: dict[str, Any]) -> tuple[str | None, int | None]:
        """Check if an alert matches any exclusion.

        Returns a tuple of (exclusion_type, exclusion_id) if a match is found.
        Returns (None, None) if no exclusion matches.
        """
        if not self._exclusions:
            return None, None

        for exclusion in self._exclusions:
            query = exclusion.get("jsonata_query", "")
            if not query:
                continue

            try:
                expression = Jsonata(query)
                result = expression.evaluate(alert)
                # If the query returns a truthy value, the alert matches the exclusion
                if result:
                    exc_type = exclusion.get("exclusion_type", "hard")
                    logger.info(
                        "Alert matched %s exclusion rule '%s' (id=%s)",
                        exc_type,
                        exclusion.get("name", "unnamed"),
                        exclusion.get("id", "unknown"),
                    )
                    return exc_type, exclusion.get("id")
            except Exception as e:
                logger.warning(
                    "Error evaluating exclusion '%s' (id=%s): %s",
                    exclusion.get("name", "unnamed"),
                    exclusion.get("id", "unknown"),
                    e,
                )
                # Continue to next exclusion even if this one fails
                continue

        return None, None

    def is_excluded(self, alert: dict[str, Any]) -> bool:
        """Check if an alert matches any exclusion.

        Returns True if the alert should be excluded (matches any exclusion query).
        Returns False if the alert should be processed.
        """
        exc_type, _ = self.check_exclusion(alert)
        # Note: Historically, is_excluded was only for hard exclusions (which filter out completely)
        # but here we preserve it for any matched exclusions (or we can return True only if hard,
        # but calling check_exclusion directly in tailer is cleaner).
        return exc_type is not None
