"""Version reporting and detection utilities for the radegast-agent."""

from __future__ import annotations

import importlib.metadata
import logging
import os
import platform
import subprocess
import tomllib
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def get_agent_version() -> str:
    """Get the agent version from package metadata or pyproject.toml."""
    try:
        return importlib.metadata.version("radegast-edr-agent")
    except Exception:
        # Fallback: try to read from pyproject.toml (for development)
        pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
        with pyproject_path.open("rb") as fh:
            data = tomllib.load(fh)
        return str(data["project"]["version"])


def get_rustinel_version(binary_path: str) -> str | None:
    """Get rustinel version by running the binary with --version flag.

    Returns the version string if the binary exists and is executable,
    otherwise returns None.
    """
    path = Path(binary_path)
    if not path.exists() or not path.is_file():
        logger.info("rustinel binary not found at %s", binary_path)
        return None

    if not os.access(binary_path, os.X_OK):
        logger.info("rustinel binary at %s is not executable", binary_path)
        return None

    try:
        result = subprocess.run(
            [str(path), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        version = result.stdout.strip()
        logger.info("rustinel version: %s", version)
        return version
    except subprocess.TimeoutExpired:
        logger.warning("rustinel --version timed out")
        return None
    except subprocess.CalledProcessError as e:
        stderr = e.stderr or ""
        logger.warning(
            "rustinel --version failed with exit code %d: %s",
            e.returncode,
            stderr.strip(),
        )
        return None
    except Exception as e:
        logger.warning("Error getting rustinel version: %s", e)
        return None


def get_os_type() -> str:
    """Get a human-readable OS type string (e.g. 'Linux', 'Windows', 'macOS').

    Uses platform.system() for the OS family and includes the distribution
    information on Linux via platform.freedesktop_os_release() when available.
    """
    system = platform.system()
    if system == "Linux":
        try:
            info = platform.freedesktop_os_release()
            name = info.get("PRETTY_NAME") or info.get("NAME") or ""
            return f"Linux {name}"
        except (OSError, AttributeError):
            return system
    if system == "Darwin":
        return f"macOS {platform.mac_ver()[0]}".strip()
    if system == "Windows":
        return f"Windows {platform.version()}".strip()
    return system or "unknown"


def report_versions_to_backend(client: Any, agent_version: str, rustinel_version: str | None) -> None:
    """Report agent and rustinel versions, and OS type to the backend.

    Args:
        client: BackendClient instance
        agent_version: The agent version string
        rustinel_version: The rustinel version string, or None if binary doesn't exist
    """
    try:
        os_type = get_os_type()
        client.report_versions(agent_version, rustinel_version, os_type=os_type)
    except Exception as e:
        logger.error("Failed to report versions to backend: %s", e)
        # Continue anyway - version reporting is not critical
