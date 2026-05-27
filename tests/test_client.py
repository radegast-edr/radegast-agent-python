"""Tests for the backend API client."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import httpx
import pytest

from agent.client import BackendClient


@pytest.fixture
def client():
    c = BackendClient("http://localhost:8000", "test-device-token")
    yield c
    c.close()


class TestLogin:
    def test_login_success(self, client):
        with patch.object(client._client, "post") as mock_post:
            mock_post.return_value = httpx.Response(200, json={"message": "ok"})
            client.login()
            mock_post.assert_called_once_with(
                "/auth/device/login",
                json={"token": "test-device-token"},
            )

    def test_login_failure(self, client):
        with patch.object(client._client, "post") as mock_post:
            mock_post.return_value = httpx.Response(401, json={"detail": "Invalid token"})
            with pytest.raises(httpx.HTTPStatusError):
                client.login()


class TestAutoRelogin:
    def test_relogin_on_401(self, client):
        call_count = 0

        def mock_request(method, path, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(401)
            return httpx.Response(200, json=[])

        with patch.object(client._client, "request", side_effect=mock_request):
            with patch.object(client, "login"):
                result = client.get_available_packs()
                assert result == []
                client.login.assert_called_once()


class TestGetAvailablePacks:
    def test_returns_pack_list(self, client):
        packs = [
            {"enabled_id": 1, "pack_name": "test-pack", "version": "1.0.0", "pack_version_id": 5, "autoupdate": True}
        ]
        with patch.object(client._client, "request") as mock:
            mock.return_value = httpx.Response(200, json=packs)
            result = client.get_available_packs()
            assert result == packs


class TestDownloadPack:
    def test_returns_bytes(self, client):
        zip_content = b"PK\x03\x04fake zip content"
        with patch.object(client._client, "request") as mock:
            mock.return_value = httpx.Response(200, content=zip_content)
            result = client.download_pack(5)
            assert result == zip_content


class TestSubmitLog:
    def test_submits_correctly(self, client):
        now = datetime.now(timezone.utc)
        with patch.object(client._client, "request") as mock:
            mock.return_value = httpx.Response(200, json={"id": 1})
            client.submit_log(time=now, content="encrypted", signature="sig123")
            mock.assert_called_once()
            call_kwargs = mock.call_args
            payload = call_kwargs.kwargs["json"]
            assert payload["content"] == "encrypted"
            assert payload["signature"] == "sig123"


class TestGetEncryptionKeys:
    def test_returns_keys(self, client):
        keys = [{"user_id": 1, "public_key": "age1abc...", "key_type": "regular"}]
        with patch.object(client._client, "request") as mock:
            mock.return_value = httpx.Response(200, json=keys)
            result = client.get_encryption_keys()
            assert result == keys


class TestSetSigningKey:
    def test_registers_key(self, client):
        with patch.object(client._client, "request") as mock:
            mock.return_value = httpx.Response(200, json={"message": "ok"})
            client.set_signing_key("base64pubkey==")
            mock.assert_called_once_with(
                "POST",
                "/devices/signing-key",
                json={"signature_public_key": "base64pubkey=="},
            )
