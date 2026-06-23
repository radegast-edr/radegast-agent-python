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

    def report_versions(
        self,
        agent_version: str,
        rustinel_version: str | None,
        os_type: str | None = None,
    ) -> None:
        """Report agent and rustinel versions, and OS type to the backend.

        This updates the device's version information in the database.
        The rustinel_version can be None if the binary doesn't exist.
        """
        params: dict[str, Any] = {"agent_version": f"python {agent_version}"}
        if rustinel_version is not None:
            params["rustinel_version"] = rustinel_version
        if os_type is not None:
            params["os"] = os_type

        resp = self._request("GET", "/packs/device/available", params=params)
        resp.raise_for_status()
        logger.info(
            "Reported versions to backend: agent=%s, rustinel=%s, os=%s",
            agent_version,
            rustinel_version,
            os_type,
        )

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

    def get_exclusions(self) -> list[dict[str, Any]]:
        """Fetch list of exclusions (JSONata queries) for this device's groups."""
        resp = self._request("GET", "/exclusions/device")
        return resp.json()["exclusions"]

    def submit_log(
        self,
        time: datetime,
        content: str,
        signature: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        rule_type: str | None = None,
        excluded_by: int | None = None,
    ) -> None:
        """Submit an encrypted log entry."""
        payload: dict[str, Any] = {
            "time": time.isoformat(),
            "content": content,
            "signature": signature,
        }
        if severity is not None:
            payload["severity"] = severity
        if rule_id is not None:
            payload["rule_id"] = rule_id
        if rule_type is not None:
            payload["rule_type"] = rule_type
        if excluded_by is not None:
            payload["excluded_by"] = excluded_by
        self._request("POST", "/logs/", json=payload)

    def set_signing_key(self, public_key_b64: str) -> None:
        """Register the device's Ed25519 signing public key."""
        self._request(
            "POST",
            "/devices/signing-key",
            json={"signature_public_key": public_key_b64},
        )
        logger.info("Signing key registered with backend")

    def set_encryption_key(self, public_key_age: str) -> None:
        """Register the device's AGE encryption public key."""
        self._request(
            "POST",
            "/devices/encryption-key",
            json={"encryption_public_key": public_key_age},
        )
        logger.info("Encryption key registered with backend")

    def close(self) -> None:
        self._client.close()
