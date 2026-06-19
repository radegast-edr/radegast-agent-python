"""Autoupdate functionality for the radegast-agent."""

from __future__ import annotations

import logging
import subprocess
import tomllib

import httpx

from radegast_edr_agent.version import get_agent_version

logger = logging.getLogger(__name__)


def get_version() -> str:
    """Get the current agent version (backward compatibility alias for get_agent_version)."""
    return get_agent_version()


def parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a version string into a tuple of integers."""
    if not version_str:
        return ()
    parts = []
    for part in version_str.split("."):
        digit_part = "".join(c for c in part if c.isdigit())
        if not digit_part:
            raise ValueError(f"No digits found in version part: {part}")
        parts.append(int(digit_part))
    return tuple(parts)


def is_newer_version(current: str, remote: str) -> bool:
    """Check if remote version is newer than current version."""
    try:
        return parse_version(remote) > parse_version(current)
    except Exception:
        return remote != current


def check_and_perform_autoupdate() -> bool:
    """Check if a new version is available on GitHub and try to autoupdate itself.

    Returns:
        bool: True if updated successfully, False otherwise.
    """
    logger.info("Checking for new agent version on GitHub...")
    try:
        url = "https://raw.githubusercontent.com/radegast-edr/radegast-agent-python/main/pyproject.toml"
        resp = httpx.get(url, timeout=15.0)
        resp.raise_for_status()

        remote_data = tomllib.loads(resp.text)
        remote_version = str(remote_data["project"]["version"])
        local_version = get_agent_version()

        logger.info(
            "Local version: %s, Remote version: %s", local_version, remote_version
        )

        if is_newer_version(local_version, remote_version):
            logger.info(
                "Newer version %s is available (current: %s). Starting autoupdate...",
                remote_version,
                local_version,
            )
            try:
                logger.info("Running: uv tool upgrade radegast-edr-agent")
                subprocess.run(
                    ["uv", "tool", "upgrade", "radegast-edr-agent"], check=True
                )
                logger.info("Successfully updated agent to version %s", remote_version)
                return True
            except Exception as e:
                logger.error(
                    "Failed to upgrade from PyPI: %s. Trying direct install from GitHub...",
                    e,
                )
                try:
                    cmd = ["uv", "tool", "install", "--upgrade", "radegast-edr-agent"]
                    logger.info("Running: %s", " ".join(cmd))
                    subprocess.run(cmd, check=True)
                    logger.info(
                        "Successfully updated agent to version %s", remote_version
                    )
                    return True
                except Exception as ex:
                    logger.error(
                        "Failed to install from PyPI: %s. Trying GitHub repository...",
                        ex,
                    )
                    try:
                        cmd = [
                            "uv",
                            "tool",
                            "install",
                            "--upgrade",
                            "https://github.com/radegast-edr/radegast-agent-python/archive/refs/heads/main.zip",
                        ]
                        logger.info("Running: %s", " ".join(cmd))
                        subprocess.run(cmd, check=True)
                        logger.info(
                            "Successfully updated agent to version %s", remote_version
                        )
                        return True
                    except Exception as ex2:
                        logger.error(
                            "Autoupdate failed during uv command execution: %s", ex2
                        )
        else:
            logger.info("Agent is up to date (version %s)", local_version)
    except Exception as e:
        logger.error("Error checking for updates: %s", e)
    return False
