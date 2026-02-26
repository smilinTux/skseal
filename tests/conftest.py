"""Shared fixtures for SKSeal tests."""

import pytest
import pgpy
from pgpy.constants import (
    PubKeyAlgorithm,
    KeyFlags,
    HashAlgorithm,
    SymmetricKeyAlgorithm,
    CompressionAlgorithm,
)
from pathlib import Path
from tempfile import TemporaryDirectory


PASSPHRASE = "test-passphrase-123"


def _generate_test_key(name: str, email: str) -> tuple[str, str]:
    """Generate a PGP keypair for testing.

    Returns:
        (private_armor, public_armor)
    """
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new(name, email=email)
    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.Certify},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.Uncompressed],
    )
    key.protect(PASSPHRASE, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    return str(key), str(key.pubkey)


@pytest.fixture
def chef_keys():
    """Generate test PGP keys for Chef."""
    return _generate_test_key("Chef", "chef@smilintux.org")


@pytest.fixture
def lumina_keys():
    """Generate test PGP keys for Lumina."""
    return _generate_test_key("Lumina", "lumina@smilintux.org")


@pytest.fixture
def tmp_store(tmp_path):
    """Create a temporary DocumentStore."""
    from skseal.store import DocumentStore

    return DocumentStore(base_dir=tmp_path)


@pytest.fixture
def sample_pdf() -> bytes:
    """Minimal valid PDF bytes for testing."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n"
        b"xref\n0 4\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"trailer<</Size 4/Root 1 0 R>>\n"
        b"startxref\n190\n%%EOF"
    )
