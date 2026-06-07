from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class BackendClient:
    """HTTP client for the radegast backend API."""

    def __init__(self, base_url: str, device_token: str):
        self._base_url = base_url.rstrip("/")
        self._device_token = device_token
        self._client = httpx.Client(
            base_url=self._base_url,
            timeout=30.0,
            follow_redirects=True,
        )

    def login(self) -> None:
        """Authenticate with the backend using the device token."""
        resp = self._client.post(
            "/auth/device/login",
            json={"token": self._device_token},
        )
        resp.raise_for_status()
        logger.info("Authenticated with backend")

    def report_versions(self, agent_version: str, rustinel_version: str | None) -> None:
        """Report agent and rustinel versions to the backend.
        
        This updates the device's version information in the database.
        The rustinel_version can be None if the binary doesn't exist.
        """
        params: dict[str, Any] = {"agent_version": f"python {agent_version}"}
        if rustinel_version is not None:
            params["rustinel_version"] = rustinel_version
        
        resp = self._request("GET", "/packs/device/available", params=params)
        resp.raise_for_status()
        logger.info("Reported versions to backend: agent=%s, rustinel=%s", agent_version, rustinel_version)

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Make an authenticated request, re-logging in on 401."""
        resp = self._client.request(method, path, **kwargs)
        if resp.status_code == 401:
            logger.info("Session expired, re-authenticating")
            self.login()
            resp = self._client.request(method, path, **kwargs)
        resp.raise_for_status()
        return resp

    def get_available_packs(self) -> list[dict[str, Any]]:
        """Fetch list of packs enabled for this device."""
        resp = self._request("GET", "/packs/device/available")
        return resp.json()

    def download_pack(self, version_id: int) -> bytes:
        """Download a pack version zip file."""
        resp = self._request("GET", f"/packs/device/download/{version_id}")
        return resp.content

    def get_encryption_keys(self) -> list[dict[str, str]]:
        """Get AGE public keys for log encryption recipients."""
        resp = self._request("GET", "/logs/encryption-keys")
        return resp.json()

    def submit_log(
        self,
        time: datetime,
        content: str,
        signature: str | None = None,
        severity: str | None = None,
    ) -> None:
        """Submit an encrypted log entry."""
        payload: dict[str, Any] = {
            "time": time.isoformat(),
            "content": content,
            "signature": signature,
        }
        if severity is not None:
            payload["severity"] = severity
        self._request("POST", "/logs/", json=payload)

    def set_signing_key(self, public_key_b64: str) -> None:
        """Register the device's Ed25519 signing public key."""
        self._request(
            "POST",
            "/devices/signing-key",
            json={"signature_public_key": public_key_b64},
        )
        logger.info("Signing key registered with backend")

    def close(self) -> None:
        self._client.close()
