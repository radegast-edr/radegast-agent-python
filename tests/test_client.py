"""Tests for the backend API client."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import httpx
import pytest

from agent.client import BackendClient


def make_response(status_code, method="GET", url="http://localhost:8000", **kwargs):
    return httpx.Response(status_code, request=httpx.Request(method, url), **kwargs)


@pytest.fixture
def client():
    c = BackendClient("http://localhost:8000", "test-device-token")
    yield c
    c.close()


class TestLogin:
    def test_login_success(self, client):
        with patch.object(client._client, "post") as mock_post:
            mock_post.return_value = make_response(
                200,
                method="POST",
                url="http://localhost:8000/auth/device/login",
                json={"message": "ok"},
            )
            client.login()
            mock_post.assert_called_once_with(
                "/auth/device/login",
                json={"token": "test-device-token"},
            )

    def test_login_failure(self, client):
        with patch.object(client._client, "post") as mock_post:
            mock_post.return_value = make_response(
                401,
                method="POST",
                url="http://localhost:8000/auth/device/login",
                json={"detail": "Invalid token"},
            )
            with pytest.raises(httpx.HTTPStatusError):
                client.login()


class TestClientConfiguration:
    def test_enables_redirects_globally(self):
        c = BackendClient("http://localhost:8000", "test-device-token")
        try:
            assert c._client.follow_redirects is True
        finally:
            c.close()


class TestAutoRelogin:
    def test_relogin_on_401(self, client):
        call_count = 0

        def mock_request(method, path, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return make_response(
                    401,
                    method=method,
                    url=f"http://localhost:8000{path}",
                )
            return make_response(
                200,
                method=method,
                url=f"http://localhost:8000{path}",
                json=[],
            )

        with patch.object(client._client, "request", side_effect=mock_request):
            with patch.object(client, "login"):
                result = client.get_available_packs()
                assert result == []
                client.login.assert_called_once()


class TestGetAvailablePacks:
    def test_returns_pack_list(self, client):
        packs = [
            {"enabled_id": 1, "pack_id": "test-pack", "version": "1.0.0", "pack_version_id": 5, "autoupdate": True}
        ]
        with patch.object(client._client, "request") as mock:
            mock.return_value = make_response(
                200,
                method="GET",
                url="http://localhost:8000/packs/device/available",
                json=packs,
            )
            result = client.get_available_packs()
            assert result == packs


class TestDownloadPack:
    def test_returns_bytes(self, client):
        zip_content = b"PK\x03\x04fake zip content"
        with patch.object(client._client, "request") as mock:
            mock.return_value = make_response(
                200,
                method="GET",
                url="http://localhost:8000/packs/device/download/5",
                content=zip_content,
            )
            result = client.download_pack(5)
            assert result == zip_content


class TestSubmitLog:
    def test_submits_correctly(self, client):
        now = datetime.now(timezone.utc)
        with patch.object(client._client, "request") as mock:
            mock.return_value = make_response(
                200,
                method="POST",
                url="http://localhost:8000/logs/",
                json={"id": 1},
            )
            client.submit_log(time=now, content="encrypted", signature="sig123")
            mock.assert_called_once()
            call_kwargs = mock.call_args
            payload = call_kwargs.kwargs["json"]
            assert payload["content"] == "encrypted"
            assert payload["signature"] == "sig123"

    def test_submits_with_severity(self, client):
        now = datetime.now(timezone.utc)
        with patch.object(client._client, "request") as mock:
            mock.return_value = make_response(
                200,
                method="POST",
                url="http://localhost:8000/logs/",
                json={"id": 1},
            )
            client.submit_log(time=now, content="encrypted", signature="sig123", severity="critical")
            mock.assert_called_once()
            call_kwargs = mock.call_args
            payload = call_kwargs.kwargs["json"]
            assert payload["content"] == "encrypted"
            assert payload["signature"] == "sig123"
            assert payload["severity"] == "critical"


class TestGetEncryptionKeys:
    def test_returns_keys(self, client):
        keys = [{"user_id": 1, "public_key": "age1abc...", "key_type": "regular"}]
        with patch.object(client._client, "request") as mock:
            mock.return_value = make_response(
                200,
                method="GET",
                url="http://localhost:8000/logs/encryption-keys",
                json=keys,
            )
            result = client.get_encryption_keys()
            assert result == keys


class TestSetSigningKey:
    def test_registers_key(self, client):
        with patch.object(client._client, "request") as mock:
            mock.return_value = make_response(
                200,
                method="POST",
                url="http://localhost:8000/devices/signing-key",
                json={"message": "ok"},
            )
            client.set_signing_key("base64pubkey==")
            mock.assert_called_once_with(
                "POST",
                "/devices/signing-key",
                json={"signature_public_key": "base64pubkey=="},
            )


class TestReportVersions:
    def test_reports_both_versions(self, client):
        with patch.object(client._client, "request") as mock:
            mock.return_value = make_response(
                200,
                method="GET",
                url="http://localhost:8000/packs/device/available?agent_version=1.0.0&rustinel_version=0.5.0",
                json=[],
            )
            client.report_versions("1.0.0", "0.5.0")
            mock.assert_called_once_with(
                "GET",
                "/packs/device/available",
                params={"agent_version": "1.0.0", "rustinel_version": "0.5.0"},
            )

    def test_reports_agent_version_only(self, client):
        with patch.object(client._client, "request") as mock:
            mock.return_value = make_response(
                200,
                method="GET",
                url="http://localhost:8000/packs/device/available?agent_version=1.0.0",
                json=[],
            )
            client.report_versions("1.0.0", None)
            mock.assert_called_once_with(
                "GET",
                "/packs/device/available",
                params={"agent_version": "1.0.0"},
            )

    def test_handles_error(self, client):
        with patch.object(client._client, "request") as mock:
            mock.return_value = make_response(
                404,
                method="GET",
                url="http://localhost:8000/packs/device/available",
                json={"detail": "Not found"},
            )
            with pytest.raises(httpx.HTTPStatusError):
                client.report_versions("1.0.0", "0.5.0")
