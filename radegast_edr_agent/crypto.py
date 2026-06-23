"""Cryptographic operations for the agent: Ed25519 signing and AGE encryption."""

from __future__ import annotations

import base64
import logging
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from ssage import SSAGE

logger = logging.getLogger(__name__)


def generate_device_keypair(key_path: Path) -> str:
    """Generate an Ed25519 keypair and save the private key to disk.

    Returns the base64-encoded public key for registration with the backend.
    """
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(private_bytes)
    key_path.chmod(0o600)

    public_b64 = base64.b64encode(public_bytes).decode()
    logger.info("Generated Ed25519 keypair, public key: %s...", public_b64[:16])
    return public_b64


def load_signing_key(key_path: Path) -> Ed25519PrivateKey:
    """Load the Ed25519 private key from disk."""
    private_bytes = key_path.read_bytes()
    return Ed25519PrivateKey.from_private_bytes(private_bytes)


def get_public_key_b64(private_key: Ed25519PrivateKey) -> str:
    """Extract base64 public key from a loaded private key."""
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(public_bytes).decode()


def sign_message(message: bytes, private_key: Ed25519PrivateKey) -> str:
    """Sign a message with Ed25519. Returns base64 signature."""
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode()


def encrypt_for_recipients(plaintext: str, public_keys: list[str]) -> str:
    """Encrypt plaintext using AGE for multiple public key recipients.

    Args:
        plaintext: The cleartext to encrypt.
        public_keys: List of AGE public keys (age1...).

    Returns:
        The armored AGE ciphertext.
    """
    if not public_keys:
        raise ValueError("At least one recipient public key required")

    s = SSAGE(public_key=public_keys[0])
    additional = public_keys[1:] if len(public_keys) > 1 else None
    return s.encrypt(plaintext, additional_recipients=additional)
