"""Tests for PKCS#11 hardware token support.

Covers:
- Module path discovery
- Token enumeration (mocked)
- Signing with hardware token (mocked)
- Public key extraction (mocked)
- Configuration dataclasses
- Engine integration (sign_document_pkcs11)
- CLI commands (token list, sign, info)
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from click.testing import CliRunner

from skseal.cli import main
from skseal.engine import SealEngine
from skseal.models import Document, DocumentStatus, Signer, SignerStatus
from skseal.pkcs11 import (
    DEFAULT_MODULE_PATHS,
    PKCS11Config,
    TokenInfo,
    _has_pkcs11,
    find_pkcs11_module,
)


engine = SealEngine()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_pkcs11_lib(tokens=None, private_keys=True):
    """Build a mock PyKCS11.PyKCS11Lib with configurable tokens.

    Args:
        tokens: List of dicts with token metadata.
        private_keys: Whether tokens have private signing keys.

    Returns:
        (mock_lib, mock_module) — the lib instance and the PyKCS11 module mock.
    """
    if tokens is None:
        tokens = [
            {
                "slot_id": 0,
                "label": "YubiKey PIV #12345678",
                "manufacturer": "Yubico",
                "model": "YubiKey 5",
                "serial": "12345678",
            }
        ]

    mock_module = MagicMock()
    mock_module.CKA_CLASS = 0
    mock_module.CKO_PRIVATE_KEY = 3
    mock_module.CKO_PUBLIC_KEY = 2
    mock_module.CKA_SIGN = 0x108
    mock_module.CKA_ID = 0x102
    mock_module.CKA_LABEL = 0x003
    mock_module.CKA_VALUE = 0x011
    mock_module.CKF_RW_SESSION = 0x02
    mock_module.CKM_SHA256_RSA_PKCS = 0x40
    mock_module.CKM_SHA384_RSA_PKCS = 0x41
    mock_module.CKM_SHA512_RSA_PKCS = 0x42
    mock_module.Mechanism = MagicMock(return_value="mock_mechanism")
    mock_module.PyKCS11Error = type("PyKCS11Error", (Exception,), {})

    mock_lib = MagicMock()
    slot_ids = [t["slot_id"] for t in tokens]
    mock_lib.getSlotList.return_value = slot_ids

    for t in tokens:
        token_info = MagicMock()
        token_info.label = t["label"]
        token_info.manufacturerID = t.get("manufacturer", "Unknown")
        token_info.model = t.get("model", "Unknown")
        token_info.serialNumber = t.get("serial", "00000000")
        mock_lib.getTokenInfo.return_value = token_info

    mock_session = MagicMock()
    if private_keys:
        mock_key_obj = MagicMock()
        mock_session.findObjects.return_value = [mock_key_obj]
        mock_session.getAttributeValue.return_value = [
            [0x01, 0x02, 0x03],  # CKA_ID
            list(b"Signing Key"),  # CKA_LABEL
        ]
        mock_session.sign.return_value = list(b"\x00" * 256)  # fake signature
    else:
        mock_session.findObjects.return_value = []

    mock_lib.openSession.return_value = mock_session

    mock_lib_cls = MagicMock()
    mock_lib_cls.return_value = mock_lib
    mock_module.PyKCS11Lib = mock_lib_cls

    return mock_lib, mock_module, mock_session


# ---------------------------------------------------------------------------
# 1. Module path discovery
# ---------------------------------------------------------------------------


class TestFindPkcs11Module:
    """Tests for find_pkcs11_module()."""

    def test_returns_none_when_no_module(self, tmp_path):
        """Returns None when no module files exist."""
        with patch("skseal.pkcs11.DEFAULT_MODULE_PATHS", [str(tmp_path / "nope.so")]):
            result = find_pkcs11_module()
        assert result is None

    def test_returns_first_existing(self, tmp_path):
        """Returns the first path that exists."""
        module_file = tmp_path / "opensc-pkcs11.so"
        module_file.write_text("fake")
        with patch(
            "skseal.pkcs11.DEFAULT_MODULE_PATHS",
            [str(tmp_path / "nope.so"), str(module_file)],
        ):
            result = find_pkcs11_module()
        assert result == str(module_file)


# ---------------------------------------------------------------------------
# 2. TokenInfo dataclass
# ---------------------------------------------------------------------------


class TestTokenInfo:
    """Tests for the TokenInfo dataclass."""

    def test_defaults(self):
        info = TokenInfo(slot_id=0, label="Test Token")
        assert info.slot_id == 0
        assert info.label == "Test Token"
        assert info.has_private_key is False
        assert info.key_id is None

    def test_with_key(self):
        info = TokenInfo(
            slot_id=1,
            label="YubiKey",
            manufacturer="Yubico",
            has_private_key=True,
            key_id="0102ab",
            key_label="Sign Key",
        )
        assert info.has_private_key is True
        assert info.key_id == "0102ab"


# ---------------------------------------------------------------------------
# 3. PKCS11Config dataclass
# ---------------------------------------------------------------------------


class TestPKCS11Config:
    """Tests for the PKCS11Config dataclass."""

    def test_defaults(self):
        config = PKCS11Config()
        assert config.module_path == ""
        assert config.pin == ""
        assert config.hash_algorithm == "sha256"

    def test_custom(self):
        config = PKCS11Config(
            module_path="/usr/lib/opensc-pkcs11.so",
            pin="123456",
            token_label="YubiKey",
            key_id="ab01",
        )
        assert config.module_path == "/usr/lib/opensc-pkcs11.so"
        assert config.pin == "123456"


# ---------------------------------------------------------------------------
# 4. list_tokens (mocked)
# ---------------------------------------------------------------------------


class TestListTokens:
    """Tests for list_tokens() with mocked PyKCS11."""

    def test_returns_token_info(self):
        mock_lib, mock_module, _ = _mock_pkcs11_lib()

        with patch.dict(sys.modules, {"PyKCS11": mock_module}):
            with patch("skseal.pkcs11._has_pkcs11", return_value=True):
                from skseal.pkcs11 import list_tokens
                tokens = list_tokens("/fake/module.so")

        assert len(tokens) == 1
        assert tokens[0].label == "YubiKey PIV #12345678"
        assert tokens[0].has_private_key is True

    def test_no_tokens(self):
        mock_lib, mock_module, _ = _mock_pkcs11_lib(tokens=[])
        mock_lib.getSlotList.return_value = []
        mock_lib_cls = MagicMock(return_value=mock_lib)
        mock_module.PyKCS11Lib = mock_lib_cls

        with patch.dict(sys.modules, {"PyKCS11": mock_module}):
            with patch("skseal.pkcs11._has_pkcs11", return_value=True):
                from skseal.pkcs11 import list_tokens
                tokens = list_tokens("/fake/module.so")

        assert tokens == []

    def test_raises_without_pkcs11(self):
        with patch("skseal.pkcs11._has_pkcs11", return_value=False):
            from skseal.pkcs11 import list_tokens
            with pytest.raises(RuntimeError, match="PyKCS11"):
                list_tokens("/fake/module.so")


# ---------------------------------------------------------------------------
# 5. sign_with_token (mocked)
# ---------------------------------------------------------------------------


class TestSignWithToken:
    """Tests for sign_with_token() with mocked PyKCS11."""

    def test_sign_returns_bytes(self):
        mock_lib, mock_module, mock_session = _mock_pkcs11_lib()

        with patch.dict(sys.modules, {"PyKCS11": mock_module}):
            with patch("skseal.pkcs11._has_pkcs11", return_value=True):
                from skseal.pkcs11 import sign_with_token
                sig = sign_with_token(
                    data=b"test data",
                    module_path="/fake/module.so",
                    pin="123456",
                )

        assert isinstance(sig, bytes)
        assert len(sig) == 256

    def test_sign_with_config(self):
        mock_lib, mock_module, mock_session = _mock_pkcs11_lib()

        config = PKCS11Config(
            module_path="/fake/module.so",
            pin="123456",
            token_label="YubiKey PIV #12345678",
        )

        with patch.dict(sys.modules, {"PyKCS11": mock_module}):
            with patch("skseal.pkcs11._has_pkcs11", return_value=True):
                from skseal.pkcs11 import sign_with_token
                sig = sign_with_token(data=b"test data", config=config)

        assert isinstance(sig, bytes)

    def test_sign_requires_pin(self):
        with patch("skseal.pkcs11._has_pkcs11", return_value=True):
            with patch("skseal.pkcs11.find_pkcs11_module", return_value="/fake.so"):
                from skseal.pkcs11 import sign_with_token
                with pytest.raises(RuntimeError, match="PIN"):
                    sign_with_token(data=b"test", module_path="/fake.so")

    def test_sign_raises_without_pkcs11(self):
        with patch("skseal.pkcs11._has_pkcs11", return_value=False):
            from skseal.pkcs11 import sign_with_token
            with pytest.raises(RuntimeError, match="PyKCS11"):
                sign_with_token(data=b"test", pin="123456")


# ---------------------------------------------------------------------------
# 6. Engine integration — sign_document_pkcs11
# ---------------------------------------------------------------------------


class TestEngineSignDocumentPkcs11:
    """Tests for SealEngine.sign_document_pkcs11() with mocked PKCS#11."""

    def test_signs_document(self, sample_pdf):
        signer = Signer(name="Token User", fingerprint="placeholder")
        doc = Document(
            title="Hardware Signed",
            signers=[signer],
            status=DocumentStatus.PENDING,
            pdf_hash=engine.hash_bytes(sample_pdf),
        )

        config = PKCS11Config(
            module_path="/fake/module.so",
            pin="123456",
            key_id="abcd01",
        )

        mock_sig = b"\x00" * 256
        with patch("skseal.pkcs11.sign_with_token", return_value=mock_sig):
            doc = engine.sign_document_pkcs11(
                document=doc,
                signer_id=signer.signer_id,
                config=config,
                pdf_data=sample_pdf,
            )

        assert doc.status == DocumentStatus.COMPLETED
        assert len(doc.signatures) == 1
        assert "PKCS11" in doc.signatures[0].signature_armor
        assert doc.signers[0].status == SignerStatus.SIGNED

    def test_cannot_sign_voided(self, sample_pdf):
        signer = Signer(name="Token User", fingerprint="placeholder")
        doc = Document(
            title="Voided",
            signers=[signer],
            status=DocumentStatus.VOIDED,
        )
        config = PKCS11Config(pin="123456")

        with pytest.raises(ValueError, match="voided"):
            engine.sign_document_pkcs11(
                document=doc,
                signer_id=signer.signer_id,
                config=config,
                pdf_data=sample_pdf,
            )

    def test_audit_trail_mentions_hardware(self, sample_pdf):
        signer = Signer(name="Token User", fingerprint="placeholder")
        doc = Document(
            title="HW Audit Test",
            signers=[signer],
            status=DocumentStatus.PENDING,
            pdf_hash=engine.hash_bytes(sample_pdf),
        )
        config = PKCS11Config(
            module_path="/fake/module.so",
            pin="123456",
            token_label="YubiKey",
        )

        with patch("skseal.pkcs11.sign_with_token", return_value=b"\x00" * 256):
            doc = engine.sign_document_pkcs11(
                document=doc,
                signer_id=signer.signer_id,
                config=config,
                pdf_data=sample_pdf,
            )

        signed_entries = [
            e for e in doc.audit_trail if "hardware token" in e.details.lower()
        ]
        assert len(signed_entries) >= 1
        assert "YubiKey" in signed_entries[0].details


# ---------------------------------------------------------------------------
# 7. CLI — token list
# ---------------------------------------------------------------------------


class TestCliTokenList:
    """Tests for the `skseal token list` CLI command."""

    def test_token_list_no_module(self):
        runner = CliRunner()
        with patch("skseal.pkcs11.find_pkcs11_module", return_value=None):
            result = runner.invoke(main, ["token", "list"])
        assert result.exit_code != 0

    def test_token_list_no_pkcs11(self):
        runner = CliRunner()
        with patch("skseal.pkcs11._has_pkcs11", return_value=False):
            with patch("skseal.pkcs11.find_pkcs11_module", return_value="/fake.so"):
                result = runner.invoke(main, ["token", "list", "--module", "/fake.so"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# 8. CLI — token info
# ---------------------------------------------------------------------------


class TestCliTokenInfo:
    """Tests for the `skseal token info` CLI command."""

    def test_token_info_without_pkcs11(self):
        runner = CliRunner()
        with patch("skseal.pkcs11._has_pkcs11", return_value=False):
            result = runner.invoke(main, ["token", "info"])
        assert result.exit_code == 0
        assert "not installed" in result.output

    def test_token_info_with_pkcs11(self):
        runner = CliRunner()
        with patch("skseal.pkcs11._has_pkcs11", return_value=True):
            with patch("skseal.pkcs11.find_pkcs11_module", return_value="/usr/lib/opensc-pkcs11.so"):
                result = runner.invoke(main, ["token", "info"])
        assert result.exit_code == 0
        assert "PKCS#11" in result.output
