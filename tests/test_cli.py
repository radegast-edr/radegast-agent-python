import sys
from unittest.mock import MagicMock, patch

import pytest

from radegast_edr_agent import cli
from radegast_edr_agent.autoupdate import (
    check_and_perform_autoupdate,
    detect_project_root,
    find_uv,
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


class TestFindUv:
    def test_finds_via_which(self, monkeypatch):
        """shutil.which succeeds → return immediately."""
        monkeypatch.setattr("radegast_edr_agent.autoupdate.shutil.which", lambda _: "/usr/bin/uv")
        assert find_uv() == "/usr/bin/uv"

    def test_finds_via_tool_bin_dir(self, tmp_path, monkeypatch):
        """UV_TOOL_BIN_DIR set and uv binary exists there."""
        monkeypatch.setattr("radegast_edr_agent.autoupdate.shutil.which", lambda _: None)
        uv_bin = tmp_path / "uv"
        uv_bin.touch()
        monkeypatch.setenv("UV_TOOL_BIN_DIR", str(tmp_path))
        assert find_uv() == str(uv_bin)

    def test_finds_via_local_bin(self, tmp_path, monkeypatch):
        """~/.local/bin/uv exists."""
        monkeypatch.setattr("radegast_edr_agent.autoupdate.shutil.which", lambda _: None)
        monkeypatch.delenv("UV_TOOL_BIN_DIR", raising=False)
        monkeypatch.delenv("CARGO_HOME", raising=False)
        local_bin = tmp_path / ".local" / "bin"
        local_bin.mkdir(parents=True)
        uv_bin = local_bin / "uv"
        uv_bin.touch()
        monkeypatch.setattr(
            "radegast_edr_agent.autoupdate.os.path.expanduser",
            lambda _: str(tmp_path),
        )
        assert find_uv() == str(uv_bin)

    def test_finds_via_cargo_bin(self, tmp_path, monkeypatch):
        """~/.cargo/bin/uv exists (fallback after .local/bin)."""
        monkeypatch.setattr("radegast_edr_agent.autoupdate.shutil.which", lambda _: None)
        monkeypatch.delenv("UV_TOOL_BIN_DIR", raising=False)
        monkeypatch.delenv("CARGO_HOME", raising=False)
        cargo_bin = tmp_path / ".cargo" / "bin"
        cargo_bin.mkdir(parents=True)
        uv_bin = cargo_bin / "uv"
        uv_bin.touch()
        monkeypatch.setattr(
            "radegast_edr_agent.autoupdate.os.path.expanduser",
            lambda _: str(tmp_path),
        )
        assert find_uv() == str(uv_bin)

    def test_returns_none_when_not_found(self, tmp_path, monkeypatch):
        """uv not found anywhere → None."""
        monkeypatch.setattr("radegast_edr_agent.autoupdate.shutil.which", lambda _: None)
        monkeypatch.delenv("UV_TOOL_BIN_DIR", raising=False)
        monkeypatch.delenv("CARGO_HOME", raising=False)
        monkeypatch.setattr(
            "radegast_edr_agent.autoupdate.os.path.expanduser",
            lambda _: str(tmp_path),
        )
        assert find_uv() is None


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
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[project]\nname = "test"\ndependencies = ["radegast-edr-agent"]\n',
            encoding="utf-8",
        )
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
def test_check_and_perform_autoupdate_no_update(mock_run, mock_get_version, mock_get) -> None:
    mock_get_version.return_value = "0.1.0"
    mock_get.return_value = _pypi_mock("0.1.0")

    updated = check_and_perform_autoupdate()
    assert updated is False
    mock_run.assert_not_called()
    mock_get.assert_called_once_with("https://pypi.org/pypi/radegast-edr-agent/json", timeout=15.0)


@patch("radegast_edr_agent.autoupdate.find_uv", return_value="/home/user/.local/bin/uv")
@patch("radegast_edr_agent.autoupdate.detect_project_root", return_value=None)
@patch("radegast_edr_agent.autoupdate.httpx.get")
@patch("radegast_edr_agent.autoupdate.get_agent_version")
@patch("radegast_edr_agent.autoupdate.subprocess.run")
def test_check_and_perform_autoupdate_tool_upgrade(
    mock_run, mock_get_version, mock_get, mock_detect, mock_find_uv
) -> None:
    """uv tool mode: runs `<uv> tool upgrade`."""
    mock_get_version.return_value = "0.1.0"
    mock_get.return_value = _pypi_mock("0.2.0")

    updated = check_and_perform_autoupdate()
    assert updated is True
    mock_run.assert_called_once_with(
        ["/home/user/.local/bin/uv", "tool", "upgrade", "radegast-edr-agent"],
        check=True,
    )


@patch("radegast_edr_agent.autoupdate.find_uv", return_value="/home/user/.local/bin/uv")
@patch("radegast_edr_agent.autoupdate.detect_project_root")
@patch("radegast_edr_agent.autoupdate.httpx.get")
@patch("radegast_edr_agent.autoupdate.get_agent_version")
@patch("radegast_edr_agent.autoupdate.subprocess.run")
def test_check_and_perform_autoupdate_project_upgrade(
    mock_run, mock_get_version, mock_get, mock_detect, mock_find_uv, tmp_path
) -> None:
    """uv project mode: runs `<uv> add --upgrade` in the project root."""
    mock_detect.return_value = tmp_path
    mock_get_version.return_value = "0.1.0"
    mock_get.return_value = _pypi_mock("0.2.0")

    updated = check_and_perform_autoupdate()
    assert updated is True
    mock_run.assert_called_once_with(
        ["/home/user/.local/bin/uv", "add", "radegast-edr-agent", "--upgrade"],
        check=True,
        cwd=str(tmp_path),
    )


@patch("radegast_edr_agent.autoupdate.find_uv", return_value=None)
@patch("radegast_edr_agent.autoupdate.detect_project_root", return_value=None)
@patch("radegast_edr_agent.autoupdate.httpx.get")
@patch("radegast_edr_agent.autoupdate.get_agent_version")
@patch("radegast_edr_agent.autoupdate.subprocess.run")
def test_check_and_perform_autoupdate_pip_fallback(
    mock_run, mock_get_version, mock_get, mock_detect, mock_find_uv
) -> None:
    """uv not found + tool mode → fall back to pip."""
    mock_get_version.return_value = "0.1.0"
    mock_get.return_value = _pypi_mock("0.2.0")

    updated = check_and_perform_autoupdate()
    assert updated is True
    mock_run.assert_called_once_with(
        [sys.executable, "-m", "pip", "install", "--upgrade", "radegast-edr-agent"],
        check=True,
    )


@patch("radegast_edr_agent.autoupdate.find_uv", return_value=None)
@patch("radegast_edr_agent.autoupdate.detect_project_root")
@patch("radegast_edr_agent.autoupdate.httpx.get")
@patch("radegast_edr_agent.autoupdate.get_agent_version")
@patch("radegast_edr_agent.autoupdate.subprocess.run")
def test_check_and_perform_autoupdate_no_uv_project_mode_fails(
    mock_run, mock_get_version, mock_get, mock_detect, mock_find_uv, tmp_path
) -> None:
    """uv not found + project mode → cannot upgrade safely, returns False."""
    mock_detect.return_value = tmp_path
    mock_get_version.return_value = "0.1.0"
    mock_get.return_value = _pypi_mock("0.2.0")

    updated = check_and_perform_autoupdate()
    assert updated is False
    mock_run.assert_not_called()


@patch("radegast_edr_agent.autoupdate.find_uv", return_value="/usr/local/bin/uv")
@patch("radegast_edr_agent.autoupdate.detect_project_root", return_value=None)
@patch("radegast_edr_agent.autoupdate.httpx.get")
@patch("radegast_edr_agent.autoupdate.get_agent_version")
@patch("radegast_edr_agent.autoupdate.subprocess.run")
def test_check_and_perform_autoupdate_upgrade_fails(
    mock_run, mock_get_version, mock_get, mock_detect, mock_find_uv
) -> None:
    mock_get_version.return_value = "0.1.0"
    mock_get.return_value = _pypi_mock("0.2.0")

    import subprocess

    mock_run.side_effect = subprocess.CalledProcessError(1, "uv")

    updated = check_and_perform_autoupdate()
    assert updated is False
    mock_run.assert_called_once_with(["/usr/local/bin/uv", "tool", "upgrade", "radegast-edr-agent"], check=True)


@patch("radegast_edr_agent.autoupdate.httpx.get")
@patch("radegast_edr_agent.autoupdate.get_agent_version")
@patch("radegast_edr_agent.autoupdate.subprocess.run")
def test_check_and_perform_autoupdate_pypi_error(mock_run, mock_get_version, mock_get) -> None:
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
@patch("radegast_edr_agent.cli.ensure_encryption_key")
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
    mock_ensure_enc_key,
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


def test_ensure_signing_key_existing(tmp_path, monkeypatch) -> None:
    key_path = tmp_path / "signing_key"
    from radegast_edr_agent.crypto import generate_device_keypair

    generate_device_keypair(key_path)

    monkeypatch.setattr(cli.settings, "signing_key_path", key_path)

    mock_client = MagicMock()
    cli.ensure_signing_key(mock_client)

    mock_client.set_signing_key.assert_not_called()


def test_ensure_signing_key_new(tmp_path, monkeypatch) -> None:
    key_path = tmp_path / "signing_key"
    monkeypatch.setattr(cli.settings, "signing_key_path", key_path)

    mock_client = MagicMock()
    cli.ensure_signing_key(mock_client)

    mock_client.set_signing_key.assert_called_once()
    assert key_path.exists()


def test_ensure_encryption_key_existing(tmp_path, monkeypatch) -> None:
    key_path = tmp_path / "enc_key"
    from radegast_edr_agent.crypto import generate_encryption_keypair

    generate_encryption_keypair(key_path)

    monkeypatch.setattr(cli.settings, "encryption_key_path", key_path)

    mock_client = MagicMock()
    cli.ensure_encryption_key(mock_client)

    mock_client.set_encryption_key.assert_not_called()


def test_ensure_encryption_key_new(tmp_path, monkeypatch) -> None:
    key_path = tmp_path / "enc_key"
    monkeypatch.setattr(cli.settings, "encryption_key_path", key_path)

    mock_client = MagicMock()
    cli.ensure_encryption_key(mock_client)

    mock_client.set_encryption_key.assert_called_once()
    assert key_path.exists()
