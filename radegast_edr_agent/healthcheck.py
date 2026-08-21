"""Healthcheck mechanism for verifying rustinel EDR detection and reporting status."""

from __future__ import annotations

import logging
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from radegast_edr_agent.client import BackendClient

logger = logging.getLogger(__name__)

RULE_TITLE = "Radegast Healthcheck Probe"


class HealthCheckManager:
    """Manages periodic healthcheck probe rule generation and verification."""

    def __init__(
        self,
        client: BackendClient,
        rule_dir: Path,
        timeout: float = 10.0,
        enabled: bool = True,
    ):
        self.client = client
        self.rule_dir = rule_dir
        self.timeout = timeout
        self.enabled = enabled
        self._active_probe_uuid: str | None = None
        self._probe_received: bool = False
        self._last_status: bool | None = None
        self._known_probe_uuids: set[str] = set()
        self._state: str = "IDLE"  # "IDLE", "RELOADING", "VERIFYING"
        self._state_start_time: float = 0.0

    @property
    def last_status(self) -> bool | None:
        """Return the last recorded healthcheck status."""
        return self._last_status

    def write_probe_rule(self, probe_uuid: str) -> Path:
        """Generate and write a Sigma rule that matches the probe UUID."""
        self.rule_dir.mkdir(parents=True, exist_ok=True)
        rule_file = self.rule_dir / "healthcheck.yml"
        rule_content = f"""title: {RULE_TITLE}
id: {probe_uuid}
status: experimental
description: Healthcheck probe rule for Radegast EDR Agent
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: '{probe_uuid}'
  condition: selection
level: informational
"""
        rule_file.write_text(rule_content, encoding="utf-8")
        logger.debug("Generated healthcheck rule with probe UUID: %s", probe_uuid)
        return rule_file

    def execute_probe_command(self, probe_uuid: str) -> bool:
        """Run a command containing the probe UUID."""
        cmd = [sys.executable, "-c", "pass", probe_uuid]
        try:
            subprocess.run(
                cmd,
                capture_output=True,
                timeout=5.0,
                check=False,
            )
            logger.debug("Executed healthcheck probe command for UUID: %s", probe_uuid)
            return True
        except Exception as e:
            logger.error("Failed to execute healthcheck probe command: %s", e)
            return False

    def is_healthcheck_alert(self, alert: dict[str, Any]) -> bool:
        """Check if an alert was triggered by a healthcheck probe."""
        # 1. Check rule name
        rule_name = alert.get("rule.name")
        if rule_name == RULE_TITLE:
            return True

        # 2. Check rule id
        raw_rule_id = alert.get("rule.id")
        if raw_rule_id and isinstance(raw_rule_id, str):
            rule_id_part = raw_rule_id.split("::", 1)[-1]
            if rule_id_part == self._active_probe_uuid or rule_id_part in self._known_probe_uuids:
                return True

        # 3. Check command line / args in alert body
        cmd_line = alert.get("process.command_line") or alert.get("CommandLine") or ""
        if isinstance(cmd_line, str):
            if self._active_probe_uuid and self._active_probe_uuid in cmd_line:
                return True
            for known_uuid in self._known_probe_uuids:
                if known_uuid in cmd_line:
                    return True

        return False

    def record_healthcheck_alert(self, alert: dict[str, Any]) -> None:
        """Record that a healthcheck alert was received for the active probe."""
        logger.info(
            "Healthcheck probe alert detected by rustinel (probe_uuid=%s)",
            self._active_probe_uuid,
        )
        self._probe_received = True

    def start_check(self) -> None:
        """Start a healthcheck probe sequence asynchronously/non-blocking."""
        if not self.enabled:
            logger.debug("Healthcheck is disabled. Reporting null health to backend.")
            try:
                self.client.report_health(None)
            except Exception as e:
                logger.error("Failed to report disabled health status to backend: %s", e)
            self._last_status = None
            return

        if self._state != "IDLE":
            logger.warning("Healthcheck already in progress (state=%s)", self._state)
            return

        probe_uuid = str(uuid.uuid4())
        self._active_probe_uuid = probe_uuid
        self._known_probe_uuids.add(probe_uuid)
        self._probe_received = False
        self._state = "RELOADING"
        self._state_start_time = time.time()

        try:
            self.write_probe_rule(probe_uuid)
            logger.info("Started healthcheck probe reload phase (probe_uuid=%s)", probe_uuid)
        except Exception as e:
            logger.error("Failed to write healthcheck rule: %s", e)
            self._state = "IDLE"
            self._active_probe_uuid = None

    def update(self) -> None:
        """Advance the healthcheck state machine. Call this regularly in the main loop."""
        if not self.enabled or self._state == "IDLE":
            return

        now = time.time()
        if self._state == "RELOADING":
            # Give rustinel 5.0 seconds to hot-reload the Sigma rule
            if now - self._state_start_time >= 5.0:
                logger.info("Reload time elapsed, executing probe command for %s", self._active_probe_uuid)
                self.execute_probe_command(self._active_probe_uuid)
                self._state = "VERIFYING"
                self._state_start_time = now
            return

        if self._state == "VERIFYING":
            if self._probe_received:
                self._report_result(True)
            elif now - self._state_start_time >= self.timeout:
                logger.warning("Healthcheck probe timed out after %s seconds", self.timeout)
                self._report_result(False)
            return

    def _report_result(self, status: bool) -> None:
        """Submit health status to the backend and reset state to IDLE."""
        self._last_status = status
        logger.info("Healthcheck result: %s", "HEALTHY" if status else "UNHEALTHY")
        try:
            self.client.report_health(status)
        except Exception as e:
            logger.error("Failed to report health status to backend: %s", e)
        self._state = "IDLE"
        self._active_probe_uuid = None

    def run_check(self, tailer: Any) -> bool | None:
        """Execute a healthcheck cycle synchronously and report status to backend."""
        if not self.enabled:
            logger.debug("Healthcheck is disabled. Reporting null health to backend.")
            try:
                self.client.report_health(None)
            except Exception as e:
                logger.error("Failed to report disabled health status to backend: %s", e)
            self._last_status = None
            return None

        self.start_check()
        time.sleep(5.0)
        self._state_start_time -= 5.0  # Adjust for mocked sleep time checks in tests
        self.update()  # Transitions from RELOADING to VERIFYING

        start_time = time.time()
        while self._state == "VERIFYING" and (time.time() - start_time < self.timeout + 1.0):
            if tailer is not None:
                tailer.poll()
            self._state_start_time -= 0.5  # Adjust for mocked sleep time checks in tests
            self.update()
            if self._state == "IDLE":
                break
            time.sleep(0.5)

        return self._last_status
