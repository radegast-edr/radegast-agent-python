from unittest.mock import MagicMock, patch

import pytest

from radegast_edr_agent import cli
from radegast_edr_agent.autoupdate import (
    check_and_perform_autoupdate,
    is_newer_version,
    parse_version,
)
from radegast_edr_agent.config import settings


def test_default_start_rustinel_is_false() -> None:
    assert settings.start_rustinel is False


class TestParseVersion:
    def test_parse_version(self) -> None:
        assert parse_version("0.1.0") == (0, 1, 0)
        assert parse_version("1.23.4") == (1, 23, 4)
        assert parse_version("v2.0.1-alpha") == (2, 0, 1)
        assert parse_version("1.0") == (1, 0)
        assert parse_version("") == ()


class TestIsNewerVersion:
    def test_is_newer_version(self) -> None:
        assert is_newer_version("0.1.0", "0.2.0") is True
        assert is_newer_version("0.1.0", "0.1.1") is True
        assert is_newer_version("0.1.0", "0.1.0") is False
        assert is_newer_version("0.2.0", "0.1.0") is False
        # Fallback comparison if parsing fails
        assert is_newer_version("abc", "def") is True
        assert is_newer_version("abc", "abc") is False


@patch("radegast_edr_agent.autoupdate.httpx.get")
@patch("radegast_edr_agent.autoupdate.get_agent_version")
@patch("radegast_edr_agent.autoupdate.subprocess.run")
def test_check_and_perform_autoupdate_no_update(
    mock_run, mock_get_version, mock_get
) -> None:
    mock_get_version.return_value = "0.1.0"

    mock_response = MagicMock()
    mock_response.text = '[project]\nversion = "0.1.0"'
    mock_get.return_value = mock_response

    updated = check_and_perform_autoupdate()
    assert updated is False
    mock_run.assert_not_called()


@patch("radegast_edr_agent.autoupdate.httpx.get")
@patch("radegast_edr_agent.autoupdate.get_agent_version")
@patch("radegast_edr_agent.autoupdate.subprocess.run")
def test_check_and_perform_autoupdate_success_upgrade(
    mock_run, mock_get_version, mock_get
) -> None:
    mock_get_version.return_value = "0.1.0"

    mock_response = MagicMock()
    mock_response.text = '[project]\nversion = "0.2.0"'
    mock_get.return_value = mock_response

    updated = check_and_perform_autoupdate()
    assert updated is True
    mock_run.assert_called_once_with(
        ["uv", "tool", "upgrade", "radegast-edr-agent"], check=True
    )


@patch("radegast_edr_agent.autoupdate.httpx.get")
@patch("radegast_edr_agent.autoupdate.get_agent_version")
@patch("radegast_edr_agent.autoupdate.subprocess.run")
def test_check_and_perform_autoupdate_fallback_install(
    mock_run, mock_get_version, mock_get
) -> None:
    mock_get_version.return_value = "0.1.0"

    mock_response = MagicMock()
    mock_response.text = '[project]\nversion = "0.2.0"'
    mock_get.return_value = mock_response

    import subprocess

    mock_run.side_effect = [
        subprocess.CalledProcessError(1, "uv"),
        subprocess.CalledProcessError(1, "uv"),
        None,
    ]

    updated = check_and_perform_autoupdate()
    assert updated is True

    assert mock_run.call_count == 3
    mock_run.assert_any_call(
        ["uv", "tool", "upgrade", "radegast-edr-agent"], check=True
    )
    mock_run.assert_any_call(
        ["uv", "tool", "install", "--upgrade", "radegast-edr-agent"], check=True
    )
    mock_run.assert_any_call(
        [
            "uv",
            "tool",
            "install",
            "--upgrade",
            "https://github.com/radegast-edr/radegast-agent-python/archive/refs/heads/main.zip",
        ],
        check=True,
    )


@patch("radegast_edr_agent.autoupdate.httpx.get")
@patch("radegast_edr_agent.autoupdate.get_agent_version")
@patch("radegast_edr_agent.autoupdate.subprocess.run")
def test_check_and_perform_autoupdate_all_fail(
    mock_run, mock_get_version, mock_get
) -> None:
    mock_get_version.return_value = "0.1.0"

    mock_response = MagicMock()
    mock_response.text = '[project]\nversion = "0.2.0"'
    mock_get.return_value = mock_response

    import subprocess

    mock_run.side_effect = subprocess.CalledProcessError(1, "uv")

    updated = check_and_perform_autoupdate()
    assert updated is False
    assert mock_run.call_count == 3


class TestCreateRadegastProcess:
    def test_skips_when_disabled(self, monkeypatch) -> None:
        monkeypatch.setattr(cli.settings, "start_rustinel", False)
        with patch("radegast_edr_agent.cli.RadegastProcess") as mock_radegast:
            radegast = cli.create_radegast_process()
        assert radegast is None
        mock_radegast.assert_not_called()

    def test_starts_when_enabled(self, monkeypatch) -> None:
        monkeypatch.setattr(cli.settings, "start_rustinel", True)
        with patch("radegast_edr_agent.cli.RadegastProcess") as mock_radegast:
            mock_instance = mock_radegast.return_value
            radegast = cli.create_radegast_process()

        mock_radegast.assert_called_once_with(
            binary=settings.rustinel_binary,
            rules_dir=settings.rules_dir,
            alerts_dir=settings.alerts_dir,
        )
        mock_instance.start.assert_called_once()
        assert radegast is mock_instance


def test_main_prints_version(capsys) -> None:
    cli.main(["--version"])
    captured = capsys.readouterr()
    assert captured.out.strip() == cli.get_version()


@patch("radegast_edr_agent.cli.BackendClient")
@patch("radegast_edr_agent.cli.ensure_signing_key")
@patch("radegast_edr_agent.cli.load_signing_key")
@patch("radegast_edr_agent.cli.PackSyncer")
@patch("radegast_edr_agent.cli.create_radegast_process")
@patch("radegast_edr_agent.cli.AlertTailer")
@patch("radegast_edr_agent.cli.check_and_perform_autoupdate")
@patch("radegast_edr_agent.cli.time.time")
@patch("radegast_edr_agent.cli.os.execvp")
def test_main_loop_triggers_autoupdate(
    mock_execvp,
    mock_time,
    mock_check_update,
    mock_tailer,
    mock_create_proc,
    mock_syncer,
    mock_load_key,
    mock_ensure_key,
    mock_client,
    monkeypatch,
) -> None:
    monkeypatch.setattr(cli.settings, "device_token", "dummy-token")
    monkeypatch.setattr(cli.settings, "agent_autoupdate_initial_delay", 90000)
    monkeypatch.setattr(cli.settings, "agent_autoupdate_interval", 86400)
    monkeypatch.setattr(cli.settings, "sync_interval", 300)

    mock_time.side_effect = [0.0, 0.0, 0.0, 95000.0, 95000.0] + [195000.0] * 10
    mock_check_update.return_value = True

    mock_execvp.side_effect = SystemExit(0)

    with pytest.raises(SystemExit):
        cli.main([])

    mock_check_update.assert_called_once()
    mock_execvp.assert_called_once()
