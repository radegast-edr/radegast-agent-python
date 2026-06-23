import subprocess
from unittest.mock import MagicMock, patch

from radegast_edr_agent.version import (
    get_agent_version,
    get_os_type,
    get_rustinel_version,
    report_versions_to_backend,
)


class TestGetAgentVersion:
    def test_returns_version_from_pyproject(self) -> None:
        """Test that get_agent_version reads from package metadata or pyproject.toml."""
        version = get_agent_version()
        assert version is not None
        assert isinstance(version, str)
        # Should be a valid version string
        assert len(version) > 0


class TestGetRustinelVersion:
    @patch("radegast_edr_agent.version.Path")
    def test_returns_none_when_binary_not_exists(self, mock_path):
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = False
        mock_path.return_value = mock_path_instance
        result = get_rustinel_version("/path/to/rustinel")
        assert result is None

    @patch("radegast_edr_agent.version.Path")
    @patch("radegast_edr_agent.version.os.access")
    def test_returns_none_when_not_executable(self, mock_access, mock_path):
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.is_file.return_value = True
        mock_path.return_value = mock_path_instance
        mock_access.return_value = False
        result = get_rustinel_version("/path/to/rustinel")
        assert result is None

    @patch("radegast_edr_agent.version.Path")
    @patch("radegast_edr_agent.version.os.access")
    @patch("radegast_edr_agent.version.subprocess.run")
    def test_returns_version_on_success(self, mock_run, mock_access, mock_path):
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.is_file.return_value = True
        mock_path_instance.__str__.return_value = "/path/to/rustinel"
        mock_path.return_value = mock_path_instance
        mock_access.return_value = True

        mock_result = MagicMock()
        mock_result.stdout = "rustinel 0.5.0\n"
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        result = get_rustinel_version("/path/to/rustinel")
        assert result == "rustinel 0.5.0"
        mock_run.assert_called_once_with(
            ["/path/to/rustinel", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )

    @patch("radegast_edr_agent.version.Path")
    @patch("radegast_edr_agent.version.os.access")
    @patch("radegast_edr_agent.version.subprocess.run")
    def test_handles_called_process_error(self, mock_run, mock_access, mock_path):
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.is_file.return_value = True
        mock_path_instance.__str__.return_value = "/path/to/rustinel"
        mock_path.return_value = mock_path_instance
        mock_access.return_value = True

        error = subprocess.CalledProcessError(1, "rustinel", stderr="Error: unknown flag")
        error.stderr = "Error: unknown flag"
        mock_run.side_effect = error

        result = get_rustinel_version("/path/to/rustinel")
        assert result is None

    @patch("radegast_edr_agent.version.Path")
    @patch("radegast_edr_agent.version.os.access")
    @patch("radegast_edr_agent.version.subprocess.run")
    def test_handles_timeout(self, mock_run, mock_access, mock_path):
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.is_file.return_value = True
        mock_path_instance.__str__.return_value = "/path/to/rustinel"
        mock_path.return_value = mock_path_instance
        mock_access.return_value = True

        mock_run.side_effect = subprocess.TimeoutExpired("rustinel", 10)

        result = get_rustinel_version("/path/to/rustinel")
        assert result is None

    @patch("radegast_edr_agent.version.Path")
    @patch("radegast_edr_agent.version.os.access")
    @patch("radegast_edr_agent.version.subprocess.run")
    def test_handles_other_exception(self, mock_run, mock_access, mock_path):
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.is_file.return_value = True
        mock_path_instance.__str__.return_value = "/path/to/rustinel"
        mock_path.return_value = mock_path_instance
        mock_access.return_value = True

        mock_run.side_effect = Exception("Unexpected error")

        result = get_rustinel_version("/path/to/rustinel")
        assert result is None


class TestReportVersionsToBackend:
    @patch("radegast_edr_agent.version.get_os_type", return_value="Ubuntu 22.04 LTS")
    @patch("radegast_edr_agent.version.logger")
    def test_reports_successfully(self, mock_logger, mock_os_type):
        mock_client = MagicMock()

        report_versions_to_backend(mock_client, "1.0.0", "0.5.0")
        mock_client.report_versions.assert_called_once_with("1.0.0", "0.5.0", os_type="Ubuntu 22.04 LTS")
        mock_logger.error.assert_not_called()

    @patch("radegast_edr_agent.version.get_os_type", return_value="Ubuntu 22.04 LTS")
    @patch("radegast_edr_agent.version.logger")
    def test_reports_with_none_rustinel_version(self, mock_logger, mock_os_type):
        mock_client = MagicMock()

        report_versions_to_backend(mock_client, "1.0.0", None)
        mock_client.report_versions.assert_called_once_with("1.0.0", None, os_type="Ubuntu 22.04 LTS")
        mock_logger.error.assert_not_called()

    @patch("radegast_edr_agent.version.get_os_type", return_value="Ubuntu 22.04 LTS")
    @patch("radegast_edr_agent.version.logger")
    def test_handles_exception(self, mock_logger, mock_os_type):
        mock_client = MagicMock()
        mock_client.report_versions.side_effect = Exception("Connection failed")

        report_versions_to_backend(mock_client, "1.0.0", "0.5.0")
        mock_logger.error.assert_called_once()
        # Should not raise, just log the error


class TestGetOsType:
    @patch("radegast_edr_agent.version.platform.system", return_value="Linux")
    @patch(
        "radegast_edr_agent.version.platform.freedesktop_os_release",
        return_value={"PRETTY_NAME": "Ubuntu 22.04 LTS"},
    )
    def test_linux_returns_pretty_name(self, mock_fdo, mock_system):
        assert get_os_type() == "Linux Ubuntu 22.04 LTS"

    @patch("radegast_edr_agent.version.platform.system", return_value="Linux")
    @patch(
        "radegast_edr_agent.version.platform.freedesktop_os_release",
        side_effect=OSError,
    )
    def test_linux_fallback_when_no_fdo(self, mock_fdo, mock_system):
        assert get_os_type() == "Linux"

    @patch("radegast_edr_agent.version.platform.system", return_value="Darwin")
    @patch(
        "radegast_edr_agent.version.platform.mac_ver",
        return_value=("13.5.1", ("", "", ""), ""),
    )
    def test_darwin_returns_macos(self, mock_ver, mock_system):
        assert get_os_type() == "macOS 13.5.1"

    @patch("radegast_edr_agent.version.platform.system", return_value="Windows")
    @patch("radegast_edr_agent.version.platform.version", return_value="10.0.19041")
    def test_windows_returns_version(self, mock_ver, mock_system):
        assert get_os_type() == "Windows 10.0.19041"

    @patch("radegast_edr_agent.version.platform.system", return_value="FreeBSD")
    def test_unknown_system_returns_system_name(self, mock_system):
        assert get_os_type() == "FreeBSD"

    @patch("radegast_edr_agent.version.platform.system", return_value="")
    def test_empty_system_returns_unknown(self, mock_system):
        assert get_os_type() == "unknown"
