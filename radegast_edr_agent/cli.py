"""CLI entry point for the radegast-agent."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time

import tomlkit

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
from radegast_edr_agent.healthcheck import HealthCheckManager
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
    if settings.healthcheck_rule_dir:
        settings.healthcheck_rule_dir.mkdir(parents=True, exist_ok=True)
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


def sync_active_response(client: BackendClient) -> None:
    """Fetch active response settings from backend and sync to rustinel config.toml."""
    try:
        config = client.get_device_config()
        enabled = config.get("response_enabled", False)
        severity = config.get("response_min_severity", "critical")

        config_path = settings.rustinel_config
        logger.info(
            "Syncing active response settings: enabled=%s, min_severity=%s to %s",
            enabled,
            severity,
            config_path,
        )

        content = ""
        if config_path.exists():
            try:
                content = config_path.read_text(encoding="utf-8")
            except Exception as e:
                logger.error("Failed to read existing rustinel config: %s", e)

        try:
            doc = tomlkit.parse(content)
        except Exception as e:
            logger.error("Failed to parse rustinel config as TOML: %s. Initializing empty config.", e)
            doc = tomlkit.document()

        if "response" not in doc:
            doc["response"] = tomlkit.table()

        doc["response"]["enabled"] = enabled
        doc["response"]["prevention_enabled"] = enabled
        doc["response"]["min_severity"] = severity.lower()

        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(tomlkit.dumps(doc), encoding="utf-8")
        except Exception as e:
            logger.error("Failed to write active response settings to %s: %s", config_path, e)

    except Exception as e:
        logger.error("Failed to sync active response settings: %s", e)


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

    # If a new encryption key was just registered, wait a configurable number of seconds for the backend
    # to re-encrypt exclusions before downloading them
    if new_encryption_key and settings.init_wait_seconds > 0:
        logger.info("Waiting %d seconds for backend to re-encrypt exclusions...", settings.init_wait_seconds)
        time.sleep(settings.init_wait_seconds)

    # Load signing key for alert signing
    signing_key = load_signing_key(settings.signing_key_path)

    # Initial pack sync
    syncer = PackSyncer(client, settings.rules_dir, settings.state_dir)
    try:
        syncer.sync()
    except Exception as e:
        logger.error("Initial pack sync failed: %s", e)
        # Continue anyway — rustinel can run without packs

    # Sync active response configuration on startup
    sync_active_response(client)

    # Initialize healthcheck manager
    healthcheck_mgr = HealthCheckManager(
        client=client,
        rule_dir=settings.healthcheck_rule_dir,
        timeout=settings.healthcheck_timeout,
        enabled=settings.healthcheck,
    )

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
        healthcheck_manager=healthcheck_mgr,
    )

    # Initial exclusion load — runs immediately so exclusions are ready before the
    # first alert is processed (not deferred to the first poll cycle).
    tailer.force_refresh_exclusions()

    # Initial healthcheck execution or disabled health report
    if not settings.healthcheck:
        try:
            client.report_health(None)
        except Exception as e:
            logger.error("Failed to report disabled health status to backend: %s", e)
    else:
        try:
            healthcheck_mgr.start_check()
        except Exception as e:
            logger.error("Initial healthcheck failed: %s", e)

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
    last_healthcheck = time.time()
    last_log_rotation = 0
    first_autoupdate_done = False
    logger.info(
        "Agent running — polling alerts every %ds, syncing packs every %ds, "
        "healthcheck every %ds (enabled=%s), "
        "first autoupdate check after %ds, then every %ds",
        POLL_INTERVAL,
        settings.sync_interval,
        settings.healthcheck_interval,
        settings.healthcheck,
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

            # Update healthcheck state machine
            if settings.healthcheck:
                try:
                    healthcheck_mgr.update()
                except Exception as e:
                    logger.error("Healthcheck update error: %s", e)

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
                try:
                    sync_active_response(client)
                except Exception as e:
                    logger.error("Active response sync error: %s", e)
                tailer.force_refresh_exclusions()
                last_sync = now

            # Periodic healthcheck
            if settings.healthcheck and (now - last_healthcheck >= settings.healthcheck_interval):
                try:
                    healthcheck_mgr.start_check()
                except Exception as e:
                    logger.error("Healthcheck error: %s", e)
                last_healthcheck = now

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
