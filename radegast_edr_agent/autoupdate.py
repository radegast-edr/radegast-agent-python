"""Autoupdate functionality for the radegast-agent."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

import httpx

from radegast_edr_agent.version import get_agent_version

logger = logging.getLogger(__name__)

PYPI_JSON_URL = "https://pypi.org/pypi/radegast-edr-agent/json"
PACKAGE_NAME = "radegast-edr-agent"


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


def detect_project_root() -> Path | None:
    """Return the uv project root if the agent is running as a uv project dependency.

    Detection strategy (in order):
    1. ``UV_PROJECT_ROOT`` env var — set by ``uv run`` when launching inside a project.
    2. Walk up from the directory of ``sys.executable`` looking for a ``pyproject.toml``
       that lists ``radegast-edr-agent`` as a dependency (covers the Windows layout where
       the venv is nested inside the project directory).

    Returns ``None`` when running as a ``uv tool`` install.
    """
    # 1. uv sets this automatically when running inside a project context
    uv_project_root = os.environ.get("UV_PROJECT_ROOT")
    if uv_project_root:
        root = Path(uv_project_root)
        if (root / "pyproject.toml").exists():
            logger.debug("Detected uv project root via UV_PROJECT_ROOT: %s", root)
            return root

    # 2. Walk up from the venv/executable directory
    search = Path(sys.executable).resolve()
    for parent in [search, *search.parents]:
        pyproject = parent / "pyproject.toml"
        if pyproject.exists():
            try:
                content = pyproject.read_text(encoding="utf-8")
                if PACKAGE_NAME in content:
                    logger.debug(
                        "Detected uv project root via pyproject.toml walk: %s", parent
                    )
                    return parent
            except OSError:
                pass

    return None


def _do_upgrade(remote_version: str) -> bool:
    """Perform the actual upgrade, choosing the right uv command based on install mode."""
    project_root = detect_project_root()

    if project_root is not None:
        logger.info(
            "Running as uv project dependency (root: %s). "
            "Upgrading via: uv add %s --upgrade",
            project_root,
            PACKAGE_NAME,
        )
        subprocess.run(
            ["uv", "add", PACKAGE_NAME, "--upgrade"],
            check=True,
            cwd=str(project_root),
        )
    else:
        logger.info(
            "Running as uv tool. Upgrading via: uv tool upgrade %s", PACKAGE_NAME
        )
        subprocess.run(["uv", "tool", "upgrade", PACKAGE_NAME], check=True)

    logger.info("Successfully updated agent to version %s", remote_version)
    return True


def check_and_perform_autoupdate() -> bool:
    """Check PyPI for a newer version and upgrade if one is available.

    Automatically detects whether the agent is installed as a ``uv tool`` or as a
    dependency inside a ``uv`` project and runs the appropriate upgrade command.

    Returns:
        bool: True if an upgrade was performed successfully, False otherwise.
    """
    logger.info("Checking for new agent version on PyPI...")
    try:
        resp = httpx.get(PYPI_JSON_URL, timeout=15.0)
        resp.raise_for_status()

        remote_version = str(resp.json()["info"]["version"])
        local_version = get_agent_version()

        logger.info(
            "Local version: %s, Remote version: %s", local_version, remote_version
        )

        if not is_newer_version(local_version, remote_version):
            logger.info("Agent is up to date (version %s)", local_version)
            return False

        logger.info(
            "Newer version %s is available (current: %s). Starting autoupdate...",
            remote_version,
            local_version,
        )
        return _do_upgrade(remote_version)

    except subprocess.CalledProcessError as e:
        logger.error("Autoupdate failed (uv returned non-zero exit code): %s", e)
    except Exception as e:
        logger.error("Autoupdate failed: %s", e)
    return False
