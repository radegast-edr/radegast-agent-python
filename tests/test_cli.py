from unittest.mock import MagicMock, patch

import pytest

from radegast_edr_agent import cli
from radegast_edr_agent.autoupdate import (
    check_and_perform_autoupdate,
    detect_project_root,
    is_newer_version,
    parse_version,
)


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


class TestDetectProjectRoot:
    def test_returns_none_when_no_markers(self, tmp_path, monkeypatch):
        """No UV_PROJECT_ROOT and no pyproject.toml → None (uv tool mode)."""
        monkeypatch.delenv("UV_PROJECT_ROOT", raising=False)
        monkeypatch.setattr(
            "radegast_edr_agent.autoupdate.sys.executable",
            str(tmp_path / "bin" / "python"),
        )
        assert detect_project_root() is None

    def test_returns_root_via_env_var(self, tmp_path, monkeypatch):
        """UV_PROJECT_ROOT env var takes priority."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nname = "test"\n', encoding="utf-8")
        monkeypatch.setenv("UV_PROJECT_ROOT", str(tmp_path))
        monkeypatch.delattr(
            "radegast_edr_agent.autoupdate.sys", raising=False
        )  # not needed
        result = detect_project_root()
        assert result == tmp_path

    def test_env_var_ignored_when_pyproject_missing(self, tmp_path, monkeypatch):
        """UV_PROJECT_ROOT set but no pyproject.toml there → falls through to walk."""
        monkeypatch.setenv("UV_PROJECT_ROOT", str(tmp_path / "nonexistent"))
        monkeypatch.setattr(
            "radegast_edr_agent.autoupdate.sys.executable",
            str(tmp_path / "bin" / "python"),
        )
        assert detect_project_root() is None

    def test_finds_pyproject_via_walk(self, tmp_path, monkeypatch):
        """Walk from sys.executable upward, find pyproject.toml mentioning the package."""
        monkeypatch.delenv("UV_PROJECT_ROOT", raising=False)
        # Create project root with pyproject.toml that mentions radegast-edr-agent
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[project]\nname = "test"\ndependencies = ["radegast-edr-agent"]\n',
            encoding="utf-8",
        )
        # Simulate executable nested inside the project
        exe = tmp_path / ".venv" / "bin" / "python"
        exe.parent.mkdir(parents=True)
        exe.touch()
        monkeypatch.setattr("radegast_edr_agent.autoupdate.sys.executable", str(exe))
        result = detect_project_root()
        assert result == tmp_path

    def test_ignores_pyproject_without_package(self, tmp_path, monkeypatch):
        """pyproject.toml that does NOT mention radegast-edr-agent is skipped."""
        monkeypatch.delenv("UV_PROJECT_ROOT", raising=False)
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nname = "unrelated"\n', encoding="utf-8")
        exe = tmp_path / ".venv" / "bin" / "python"
        exe.parent.mkdir(parents=True)
        exe.touch()
        monkeypatch.setattr("radegast_edr_agent.autoupdate.sys.executable", str(exe))
        assert detect_project_root() is None


# --- Autoupdate integration tests ------------------------------------------------


def _pypi_mock(version: str) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = {"info": {"version": version}}
    return resp


@patch("radegast_edr_agent.autoupdate.httpx.get")
@patch("radegast_edr_agent.autoupdate.get_agent_version")
@patch("radegast_edr_agent.autoupdate.subprocess.run")
def test_check_and_perform_autoupdate_no_update(
    mock_run, mock_get_version, mock_get
) -> None:
    mock_get_version.return_value = "0.1.0"
    mock_get.return_value = _pypi_mock("0.1.0")

    updated = check_and_perform_autoupdate()
    assert updated is False
    mock_run.assert_not_called()
    mock_get.assert_called_once_with(
        "https://pypi.org/pypi/radegast-edr-agent/json", timeout=15.0
    )


@patch("radegast_edr_agent.autoupdate.detect_project_root", return_value=None)
@patch("radegast_edr_agent.autoupdate.httpx.get")
@patch("radegast_edr_agent.autoupdate.get_agent_version")
@patch("radegast_edr_agent.autoupdate.subprocess.run")
def test_check_and_perform_autoupdate_tool_upgrade(
    mock_run, mock_get_version, mock_get, mock_detect
) -> None:
    """When not in a project (uv tool), runs `uv tool upgrade`."""
    mock_get_version.return_value = "0.1.0"
    mock_get.return_value = _pypi_mock("0.2.0")

    updated = check_and_perform_autoupdate()
    assert updated is True
    mock_run.assert_called_once_with(
        ["uv", "tool", "upgrade", "radegast-edr-agent"], check=True
    )


@patch("radegast_edr_agent.autoupdate.detect_project_root")
@patch("radegast_edr_agent.autoupdate.httpx.get")
@patch("radegast_edr_agent.autoupdate.get_agent_version")
@patch("radegast_edr_agent.autoupdate.subprocess.run")
def test_check_and_perform_autoupdate_project_upgrade(
    mock_run, mock_get_version, mock_get, mock_detect, tmp_path
) -> None:
    """When running as a uv project dependency, runs `uv add --upgrade` in the project root."""
    mock_detect.return_value = tmp_path
    mock_get_version.return_value = "0.1.0"
    mock_get.return_value = _pypi_mock("0.2.0")

    updated = check_and_perform_autoupdate()
    assert updated is True
    mock_run.assert_called_once_with(
        ["uv", "add", "radegast-edr-agent", "--upgrade"],
        check=True,
        cwd=str(tmp_path),
    )


@patch("radegast_edr_agent.autoupdate.detect_project_root", return_value=None)
@patch("radegast_edr_agent.autoupdate.httpx.get")
@patch("radegast_edr_agent.autoupdate.get_agent_version")
@patch("radegast_edr_agent.autoupdate.subprocess.run")
def test_check_and_perform_autoupdate_upgrade_fails(
    mock_run, mock_get_version, mock_get, mock_detect
) -> None:
    mock_get_version.return_value = "0.1.0"
    mock_get.return_value = _pypi_mock("0.2.0")

    import subprocess

    mock_run.side_effect = subprocess.CalledProcessError(1, "uv")

    updated = check_and_perform_autoupdate()
    assert updated is False
    mock_run.assert_called_once_with(
        ["uv", "tool", "upgrade", "radegast-edr-agent"], check=True
    )


@patch("radegast_edr_agent.autoupdate.httpx.get")
@patch("radegast_edr_agent.autoupdate.get_agent_version")
@patch("radegast_edr_agent.autoupdate.subprocess.run")
def test_check_and_perform_autoupdate_pypi_error(
    mock_run, mock_get_version, mock_get
) -> None:
    mock_get_version.return_value = "0.1.0"
    mock_get.side_effect = Exception("Network error")

    updated = check_and_perform_autoupdate()
    assert updated is False
    mock_run.assert_not_called()


def test_main_prints_version(capsys) -> None:
    cli.main(["--version"])
    captured = capsys.readouterr()
    assert captured.out.strip() == cli.get_version()


@patch("radegast_edr_agent.cli.BackendClient")
@patch("radegast_edr_agent.cli.ensure_signing_key")
@patch("radegast_edr_agent.cli.load_signing_key")
@patch("radegast_edr_agent.cli.PackSyncer")
@patch("radegast_edr_agent.cli.AlertTailer")
@patch("radegast_edr_agent.cli.check_and_perform_autoupdate")
@patch("radegast_edr_agent.cli.time.time")
@patch("radegast_edr_agent.cli.os.execvp")
def test_main_loop_triggers_autoupdate(
    mock_execvp,
    mock_time,
    mock_check_update,
    mock_tailer,
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
