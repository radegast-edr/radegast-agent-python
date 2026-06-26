"""CLI entry point for the radegast-agent."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time

from radegast_edr_agent.autoupdate import check_and_perform_autoupdate
from radegast_edr_agent.client import BackendClient
from radegast_edr_agent.config import settings
from radegast_edr_agent.crypto import (
    generate_device_keypair,
    generate_encryption_keypair,
    get_encryption_public_key,
    get_public_key_b64,
    load_encryption_key,
    load_signing_key,
)
from radegast_edr_agent.packs import PackSyncer, ensure_placeholders_and_ioc
from radegast_edr_agent.tailer import AlertTailer, rotate_rustinel_logs
from radegast_edr_agent.version import (
    get_agent_version,
    get_rustinel_version,
    report_versions_to_backend,
)

logger = logging.getLogger("agent")

POLL_INTERVAL = 2  # seconds between alert tail polls


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Radegast Agent")
    parser.add_argument(
        "-V",
        "--version",
        action="store_true",
        help="Show package version and exit",
    )
    return parser.parse_args(argv)


def get_version() -> str:
    """Get the agent version from pyproject.toml (kept for backward compatibility)."""
    return get_agent_version()


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def ensure_directories() -> None:
    """Create required directories."""
    settings.rules_dir.mkdir(parents=True, exist_ok=True)
    settings.alerts_dir.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    # Ensure radegast rule subdirectories exist
    (settings.rules_dir / "sigma").mkdir(exist_ok=True)
    (settings.rules_dir / "yara").mkdir(exist_ok=True)
    (settings.rules_dir / "ioc").mkdir(exist_ok=True)
    ensure_placeholders_and_ioc(settings.rules_dir)


def ensure_signing_key(client: BackendClient) -> None:
    """Load or generate the device signing keypair, registering with the backend if new."""
    key_path = settings.signing_key_path

    if key_path.exists():
        private_key = load_signing_key(key_path)
        public_b64 = get_public_key_b64(private_key)
        logger.info("Loaded existing signing key: %s...", public_b64[:16])
    else:
        logger.info("No signing key found, generating new keypair")
        public_b64 = generate_device_keypair(key_path)
        client.set_signing_key(public_b64)


def ensure_encryption_key(client: BackendClient) -> bool:
    """Load or generate the device encryption keypair, registering with the backend if new.

    Returns True if a new encryption key was generated and registered, False if loaded existing.
    """
    key_path = settings.encryption_key_path
    if key_path is None:
        return False

    if key_path.exists():
        private_key = load_encryption_key(key_path)
        public_key = get_encryption_public_key(private_key)
        logger.info("Loaded existing encryption key: %s...", public_key[:16])
        return False
    else:
        logger.info("No encryption key found, generating new keypair")
        public_key = generate_encryption_keypair(key_path)
        client.set_encryption_key(public_key)
        return True


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if args.version:
        print(get_version())
        return

    setup_logging()

    if not settings.device_token:
        logger.error("RADEGAST_AGENT_DEVICE_TOKEN is required")
        sys.exit(1)

    ensure_directories()

    # Initialize backend client and authenticate
    client = BackendClient(settings.backend_url, settings.device_token)
    logger.info("Connecting to backend at %s", settings.backend_url)

    try:
        client.login()
    except Exception as e:
        logger.error("Failed to authenticate with backend: %s", e)
        sys.exit(1)

    # Report versions to backend on startup
    report_versions_to_backend(client, get_agent_version(), get_rustinel_version(settings.rustinel_binary))

    # Ensure we have a signing key registered
    ensure_signing_key(client)

    # Ensure we have an encryption key registered
    new_encryption_key = ensure_encryption_key(client)

    # If a new encryption key was just registered, wait 90 seconds for the backend
    # to re-encrypt exclusions before downloading them
    if new_encryption_key:
        logger.info("Waiting 90 seconds for backend to re-encrypt exclusions...")
        time.sleep(90)

    # Load signing key for alert signing
    signing_key = load_signing_key(settings.signing_key_path)

    # Initial pack sync
    syncer = PackSyncer(client, settings.rules_dir, settings.state_dir)
    try:
        syncer.sync()
    except Exception as e:
        logger.error("Initial pack sync failed: %s", e)
        # Continue anyway — rustinel can run without packs

    # Initialize alert tailer
    tailer = AlertTailer(
        client=client,
        signing_key=signing_key,
        alerts_dir=settings.alerts_dir,
        alerts_filename=settings.alerts_filename,
        state_dir=settings.state_dir,
        send_severity=settings.send_severity,
        send_rule_id=settings.send_rule_id,
        enable_exclusions=True,
        send_excluded_by=settings.send_excluded_by,
    )

    # Initial exclusion load — runs immediately so exclusions are ready before the
    # first alert is processed (not deferred to the first poll cycle).
    tailer.force_refresh_exclusions()

    # Graceful shutdown handler
    shutdown = False

    def handle_signal(signum, frame):
        nonlocal shutdown
        sig_name = signal.Signals(signum).name
        logger.info("Received %s, shutting down...", sig_name)
        shutdown = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Main loop
    last_sync = time.time()
    last_autoupdate = time.time()
    last_log_rotation = 0
    first_autoupdate_done = False
    logger.info(
        "Agent running — polling alerts every %ds, syncing packs every %ds, "
        "first autoupdate check after %ds, then every %ds",
        POLL_INTERVAL,
        settings.sync_interval,
        settings.agent_autoupdate_initial_delay,
        settings.agent_autoupdate_interval,
    )

    try:
        while not shutdown:
            # Poll for new alerts
            try:
                tailer.poll()
            except Exception as e:
                logger.error("Alert poll error: %s", e)

            now = time.time()

            # Periodic log rotation
            if now - last_log_rotation >= 60:
                try:
                    rotate_rustinel_logs(
                        settings.alerts_dir,
                        settings.max_log_size_mb,
                        settings.max_log_age_days,
                    )
                except Exception as e:
                    logger.error("Log rotation error: %s", e)
                last_log_rotation = now

            # Periodic pack sync — also force-refresh exclusions so group config stays in sync
            if now - last_sync >= settings.sync_interval:
                try:
                    syncer.sync()
                except Exception as e:
                    logger.error("Pack sync error: %s", e)
                tailer.force_refresh_exclusions()
                last_sync = now

            # Periodic autoupdate check
            # First check after initial delay, subsequent checks after interval
            autoupdate_delay = (
                settings.agent_autoupdate_initial_delay
                if not first_autoupdate_done
                else settings.agent_autoupdate_interval
            )
            if now - last_autoupdate >= autoupdate_delay:
                try:
                    updated = check_and_perform_autoupdate()
                    if updated:
                        logger.info("Agent upgraded. Restarting process...")
                        client.close()
                        os.execvp(sys.argv[0], sys.argv)
                except Exception as e:
                    logger.error("Autoupdate error: %s", e)
                last_autoupdate = now
                first_autoupdate_done = True

            time.sleep(POLL_INTERVAL)
    finally:
        client.close()
        logger.info("Agent stopped")


if __name__ == "__main__":
    main()
