"""Tests for the CLI startup behavior."""

from unittest.mock import patch

from agent import cli
from agent.config import settings


def test_default_start_radegast_is_false() -> None:
    assert settings.start_radegast is False


def test_create_radegast_process_skips_when_disabled(monkeypatch) -> None:
    monkeypatch.setattr(cli.settings, "start_radegast", False)
    with patch("agent.cli.RadegastProcess") as mock_radegast:
        radegast = cli.create_radegast_process()
    assert radegast is None
    mock_radegast.assert_not_called()


def test_create_radegast_process_starts_when_enabled(monkeypatch) -> None:
    monkeypatch.setattr(cli.settings, "start_radegast", True)
    with patch("agent.cli.RadegastProcess") as mock_radegast:
        mock_instance = mock_radegast.return_value
        radegast = cli.create_radegast_process()

    mock_radegast.assert_called_once_with(
        binary=settings.radegast_binary,
        rules_dir=settings.rules_dir,
        alerts_dir=settings.alerts_dir,
    )
    mock_instance.start.assert_called_once()
    assert radegast is mock_instance
