"""Radegast subprocess management with automatic restart on crash."""

from __future__ import annotations

import logging
import signal
import subprocess
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_BACKOFF = 60  # seconds
INITIAL_BACKOFF = 2  # seconds


class RadegastProcess:
    """Manages the radegast EDR process lifecycle."""

    def __init__(self, binary: str, rules_dir: Path, alerts_dir: Path):
        self._binary = binary
        self._rules_dir = rules_dir
        self._alerts_dir = alerts_dir
        self._process: subprocess.Popen | None = None
        self._should_run = False
        self._thread: threading.Thread | None = None
        self._backoff = INITIAL_BACKOFF

    def start(self) -> None:
        """Start the radegast process in a background thread with auto-restart."""
        self._should_run = True
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="radegast"
        )
        self._thread.start()

    def stop(self) -> None:
        """Gracefully stop the radegast process."""
        self._should_run = False
        if self._process and self._process.poll() is None:
            logger.info("Sending SIGTERM to radegast (pid=%d)", self._process.pid)
            self._process.send_signal(signal.SIGTERM)
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logger.warning("Radegast did not exit gracefully, sending SIGKILL")
                self._process.kill()
                self._process.wait()
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def _run_loop(self) -> None:
        """Main loop: start radegast, restart on crash with backoff."""
        while self._should_run:
            try:
                self._spawn()
                # Reset backoff on successful start that ran for a while
                start_time = time.time()
                returncode = self._process.wait()
                run_duration = time.time() - start_time

                if not self._should_run:
                    break

                if returncode == 0:
                    logger.info("Radegast exited cleanly (code 0)")
                    break
                else:
                    logger.warning(
                        "Radegast exited with code %d after %.1fs",
                        returncode,
                        run_duration,
                    )

                # Reset backoff if it ran for more than 60 seconds
                if run_duration > 60:
                    self._backoff = INITIAL_BACKOFF

                logger.info("Restarting radegast in %ds...", self._backoff)
                # Sleep in small increments to check _should_run
                for _ in range(self._backoff * 10):
                    if not self._should_run:
                        return
                    time.sleep(0.1)

                self._backoff = min(self._backoff * 2, MAX_BACKOFF)

            except Exception as e:
                logger.error("Error in radegast process loop: %s", e)
                if not self._should_run:
                    break
                time.sleep(self._backoff)

    def _spawn(self) -> None:
        """Spawn the radegast process."""
        cmd = [self._binary, "run"]
        logger.info("Starting radegast: %s", " ".join(cmd))

        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(self._rules_dir.parent),  # radegast expects rules/ relative to CWD
        )

        # Start a thread to drain stdout and log it
        threading.Thread(
            target=self._drain_output,
            daemon=True,
            name="radegast-stdout",
        ).start()

    def _drain_output(self) -> None:
        """Read radegast stdout/stderr and forward to our logger."""
        if not self._process or not self._process.stdout:
            return
        for raw_line in self._process.stdout:
            line = raw_line.decode(errors="replace").rstrip()
            if line:
                logger.debug("[radegast] %s", line)
