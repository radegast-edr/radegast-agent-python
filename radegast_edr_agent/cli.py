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
from radegast_edr_agent.crypto import generate_device_keypair, get_public_key_b64, load_signing_key
from radegast_edr_agent.packs import PackSyncer, ensure_placeholders_and_ioc
from radegast_edr_agent.process import RadegastProcess
from radegast_edr_agent.tailer import AlertTailer
from radegast_edr_agent.version import get_agent_version, get_rustinel_version, report_versions_to_backend

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


def create_radegast_process() -> RadegastProcess | None:
    """Create and start radegast when enabled by config."""
    if not settings.start_rustinel:
        logger.info(
            "START_RUSTINEL is disabled; only checking alerts in %s",
            settings.alerts_dir,
        )
        return None

    radegast = RadegastProcess(
        binary=settings.rustinel_binary,
        rules_dir=settings.rules_dir,
        alerts_dir=settings.alerts_dir,
    )
    radegast.start()
    return radegast


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

    # Load signing key for alert signing
    signing_key = load_signing_key(settings.signing_key_path)

    # Initial pack sync
    syncer = PackSyncer(client, settings.rules_dir, settings.state_dir)
    try:
        syncer.sync()
    except Exception as e:
        logger.error("Initial pack sync failed: %s", e)
        # Continue anyway — radegast can run without packs

    # Start radegast process if configured
    radegast = create_radegast_process()

    # Initialize alert tailer
    tailer = AlertTailer(
        client=client,
        signing_key=signing_key,
        alerts_dir=settings.alerts_dir,
        alerts_filename=settings.alerts_filename,
        state_dir=settings.state_dir,
        log_severity=settings.log_severity,
    )

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
    if settings.agent_autoupdate_time is not None:
        logger.info("Agent running — polling alerts every %ds, syncing packs every %ds, checking autoupdate every %ds",
                    POLL_INTERVAL, settings.sync_interval, settings.agent_autoupdate_time)
    else:
        logger.info("Agent running — polling alerts every %ds, syncing packs every %ds",
                    POLL_INTERVAL, settings.sync_interval)

    try:
        while not shutdown:
            # Poll for new alerts
            try:
                tailer.poll()
            except Exception as e:
                logger.error("Alert poll error: %s", e)

            now = time.time()
            # Periodic pack sync
            if now - last_sync >= settings.sync_interval:
                try:
                    syncer.sync()
                except Exception as e:
                    logger.error("Pack sync error: %s", e)
                last_sync = now

            # Periodic autoupdate check
            if (
                settings.agent_autoupdate_time is not None
                and now - last_autoupdate >= settings.agent_autoupdate_time
            ):
                try:
                    updated = check_and_perform_autoupdate()
                    if updated:
                        logger.info("Agent upgraded. Restarting process...")
                        if radegast is not None:
                            logger.info("Stopping radegast process...")
                            radegast.stop()
                        client.close()
                        os.execvp(sys.argv[0], sys.argv)
                except Exception as e:
                    logger.error("Autoupdate error: %s", e)
                last_autoupdate = now

            time.sleep(POLL_INTERVAL)
    finally:
        if radegast is not None:
            logger.info("Stopping radegast process...")
            radegast.stop()
        client.close()
        logger.info("Agent stopped")


if __name__ == "__main__":
    main()
