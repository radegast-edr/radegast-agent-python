"""Tests for crypto module."""

import tempfile
from pathlib import Path

from radegast_edr_agent.crypto import (
    encrypt_for_recipients,
    generate_device_keypair,
    generate_encryption_keypair,
    get_encryption_public_key,
    get_public_key_b64,
    load_encryption_key,
    load_signing_key,
    sign_message,
)


def test_keypair_generation_and_loading():
    """Test Ed25519 keypair generation, storage, and loading."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = Path(tmpdir) / "test_key"
        public_b64 = generate_device_keypair(key_path)

        assert key_path.exists()
        assert len(public_b64) > 0

        # Load and verify
        private_key = load_signing_key(key_path)
        loaded_public = get_public_key_b64(private_key)
        assert loaded_public == public_b64


def test_sign_and_verify():
    """Test Ed25519 signing produces a valid base64 signature."""
    import base64

    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = Path(tmpdir) / "test_key"
        generate_device_keypair(key_path)
        private_key = load_signing_key(key_path)

        message = b"test alert log line"
        signature = sign_message(message, private_key)

        # Verify it's valid base64
        sig_bytes = base64.b64decode(signature)
        assert len(sig_bytes) == 64  # Ed25519 signatures are 64 bytes

        # Verify using cryptography directly

        public_key = private_key.public_key()
        public_key.verify(sig_bytes, message)  # Raises if invalid


def test_age_encryption():
    """Test AGE encryption to multiple recipients."""
    from ssage import SSAGE

    # Generate two recipient keypairs
    priv1 = SSAGE.generate_private_key()
    s1 = SSAGE(priv1)
    pub1 = s1.public_key

    priv2 = SSAGE.generate_private_key()
    s2 = SSAGE(priv2)
    pub2 = s2.public_key

    plaintext = '{"@timestamp":"2026-01-01T00:00:00Z","rule.name":"test"}'
    encrypted = encrypt_for_recipients(plaintext, [pub1, pub2])

    # Both recipients should be able to decrypt
    decrypted1 = s1.decrypt(encrypted)
    assert decrypted1 == plaintext

    decrypted2 = s2.decrypt(encrypted)
    assert decrypted2 == plaintext


def test_age_encryption_single_recipient():
    """Test AGE encryption with a single recipient."""
    from ssage import SSAGE

    priv = SSAGE.generate_private_key()
    s = SSAGE(priv)
    pub = s.public_key

    plaintext = "single recipient test"
    encrypted = encrypt_for_recipients(plaintext, [pub])

    decrypted = s.decrypt(encrypted)
    assert decrypted == plaintext


def test_encryption_keypair_generation_and_loading():
    """Test AGE encryption keypair generation, storage, and loading."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = Path(tmpdir) / "test_enc_key"
        public_key = generate_encryption_keypair(key_path)

        assert key_path.exists()
        assert len(public_key) > 0
        assert public_key.startswith("age1")

        # Load and verify
        private_key = load_encryption_key(key_path)
        loaded_public = get_encryption_public_key(private_key)
        assert loaded_public == public_key
