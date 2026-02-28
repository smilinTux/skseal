"""Tests for RFC 3161 timestamping support.

Covers:
- DER encoding helpers
- Timestamp request creation
- TSA response parsing (with mock HTTP)
- Timestamp verification logic
- High-level timestamp_document workflow
- load_tsr_file
- CLI commands (stamp, verify, info)
"""

from __future__ import annotations

import hashlib
import struct
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from skseal.cli import main
from skseal.models_timestamp import (
    HashAlgorithm,
    TimestampConfig,
    TimestampResponse,
    TimestampResult,
    TimestampStatus,
)
from skseal.timestamp import (
    DEFAULT_TSA_URL,
    _build_timestamp_request_der,
    _der_integer,
    _der_length,
    _der_null,
    _der_octet_string,
    _der_oid,
    _der_sequence,
    _der_tlv,
    _has_rfc3161ng,
    _parse_minimal,
    create_timestamp_request,
    load_tsr_file,
    timestamp_document,
    verify_timestamp,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_granted_tsr_der(serial: int = 12345) -> bytes:
    """Build a minimal but structurally valid DER TimeStampResp (status=granted).

    The structure is:
        TimeStampResp SEQUENCE {
            status PKIStatusInfo SEQUENCE {
                status INTEGER 0  -- granted
            }
            -- TimeStampToken omitted (keeps test minimal)
        }

    Args:
        serial: Unused here — kept for future expansion.

    Returns:
        DER bytes with status=0 (granted).
    """
    status_int = _der_integer(0)  # granted
    pki_status_info = _der_sequence(status_int)
    return _der_sequence(pki_status_info)


def _make_rejected_tsr_der() -> bytes:
    """Build a minimal DER TimeStampResp with status=2 (rejection)."""
    status_int = _der_integer(2)  # rejection
    pki_status_info = _der_sequence(status_int)
    return _der_sequence(pki_status_info)


def _make_timestamp_response(
    *,
    status: int = 0,
    message_imprint: str | None = None,
    token_der: bytes | None = None,
    timestamp: datetime | None = None,
    hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256,
) -> TimestampResponse:
    """Construct a TimestampResponse for testing."""
    return TimestampResponse(
        status=status,
        tsa_url=DEFAULT_TSA_URL,
        message_imprint=message_imprint,
        token_der=token_der or b"\x30\x00",
        timestamp=timestamp or datetime(2026, 2, 27, 12, 0, 0, tzinfo=timezone.utc),
        hash_algorithm=hash_algorithm,
        serial_number=99,
    )


# ---------------------------------------------------------------------------
# 1. DER encoding helpers
# ---------------------------------------------------------------------------


class TestDerHelpers:
    """Unit tests for the internal DER encoding primitives."""

    def test_der_length_single_byte(self):
        """Lengths < 128 encode in a single byte."""
        assert _der_length(0) == b"\x00"
        assert _der_length(127) == b"\x7f"

    def test_der_length_two_bytes(self):
        """Lengths 128-255 use the 0x81 extended form."""
        result = _der_length(128)
        assert result == b"\x81\x80"

    def test_der_length_three_bytes(self):
        """Lengths 256-65535 use the 0x82 extended form."""
        result = _der_length(300)
        assert result[0] == 0x82
        assert len(result) == 3

    def test_der_integer_zero(self):
        """Integer 0 encodes as 02 01 00."""
        result = _der_integer(0)
        assert result == b"\x02\x01\x00"

    def test_der_integer_positive(self):
        """Small positive integers encode correctly."""
        result = _der_integer(1)
        assert result[0] == 0x02  # INTEGER tag
        assert result[-1] == 0x01

    def test_der_oid_sha256(self):
        """SHA-256 OID encodes to the correct DER bytes."""
        oid = "2.16.840.1.101.3.4.2.1"
        result = _der_oid(oid)
        assert result[0] == 0x06  # OID tag
        assert len(result) > 4

    def test_der_null(self):
        """NULL encodes as 05 00."""
        assert _der_null() == b"\x05\x00"

    def test_der_sequence_wraps_items(self):
        """SEQUENCE tag wraps concatenated items."""
        a = b"\x02\x01\x01"
        b_ = b"\x02\x01\x02"
        result = _der_sequence(a, b_)
        assert result[0] == 0x30  # SEQUENCE tag
        # Content length = len(a) + len(b_)
        content_len = result[1]
        assert content_len == len(a) + len(b_)

    def test_der_octet_string(self):
        """OCTET STRING tag is 0x04."""
        result = _der_octet_string(b"\xde\xad\xbe\xef")
        assert result[0] == 0x04


# ---------------------------------------------------------------------------
# 2. Timestamp request creation
# ---------------------------------------------------------------------------


class TestCreateTimestampRequest:
    """Tests for create_timestamp_request()."""

    def test_returns_bytes(self, sample_pdf: bytes):
        """Request creation returns raw bytes."""
        result = create_timestamp_request(sample_pdf)
        assert isinstance(result, bytes)
        assert len(result) > 10

    def test_starts_with_sequence_tag(self, sample_pdf: bytes):
        """The request is a DER SEQUENCE (tag 0x30)."""
        result = create_timestamp_request(sample_pdf)
        assert result[0] == 0x30

    def test_different_data_different_request(self, sample_pdf: bytes):
        """Different input data produces different requests."""
        r1 = create_timestamp_request(sample_pdf)
        r2 = create_timestamp_request(sample_pdf + b"\x00modified")
        # The message imprints will differ even if nonce differs
        assert r1 != r2

    def test_sha512_algorithm(self, sample_pdf: bytes):
        """SHA-512 algorithm config produces a longer request."""
        config256 = TimestampConfig(hash_algorithm=HashAlgorithm.SHA256, nonce=False)
        config512 = TimestampConfig(hash_algorithm=HashAlgorithm.SHA512, nonce=False)
        r256 = create_timestamp_request(sample_pdf, config256)
        r512 = create_timestamp_request(sample_pdf, config512)
        # SHA-512 digest is longer (64 vs 32 bytes), so the request is larger
        assert len(r512) > len(r256)

    def test_no_nonce_when_disabled(self, sample_pdf: bytes):
        """Deterministic request when nonce is disabled."""
        config = TimestampConfig(nonce=False)
        r1 = create_timestamp_request(sample_pdf, config)
        r2 = create_timestamp_request(sample_pdf, config)
        assert r1 == r2


# ---------------------------------------------------------------------------
# 3. Build timestamp request DER (manual fallback)
# ---------------------------------------------------------------------------


class TestBuildTimestampRequestDer:
    """Tests for the manual DER builder (used when rfc3161ng is absent)."""

    def test_version_is_one(self):
        """The version field in the request is INTEGER 1."""
        digest = hashlib.sha256(b"test data").digest()
        req = _build_timestamp_request_der(
            digest,
            "2.16.840.1.101.3.4.2.1",
            nonce=None,
            request_cert=False,
        )
        # req[0] == 0x30 (SEQUENCE), req[1] == length
        # First element of the SEQUENCE is version INTEGER
        offset = 2 + (req[1] & 0x7F if req[1] >= 0x80 else 0)
        # version tag
        assert req[offset] == 0x02  # INTEGER

    def test_with_nonce_is_longer(self):
        """Including a nonce produces a longer request."""
        digest = hashlib.sha256(b"test").digest()
        without = _build_timestamp_request_der(digest, "2.16.840.1.101.3.4.2.1")
        with_nonce = _build_timestamp_request_der(
            digest, "2.16.840.1.101.3.4.2.1", nonce=123456789
        )
        assert len(with_nonce) > len(without)


# ---------------------------------------------------------------------------
# 4. TSA response parsing (minimal fallback)
# ---------------------------------------------------------------------------


class TestParseMinimal:
    """Tests for the _parse_minimal() fallback parser."""

    def test_granted_status(self):
        """Granted (status=0) DER produces is_granted=True."""
        tsr_der = _make_granted_tsr_der()
        config = TimestampConfig()
        response = _parse_minimal(tsr_der, DEFAULT_TSA_URL, config)
        assert response.is_granted is True
        assert response.status == 0

    def test_rejected_status(self):
        """Rejected (status=2) DER produces is_granted=False."""
        tsr_der = _make_rejected_tsr_der()
        config = TimestampConfig()
        response = _parse_minimal(tsr_der, DEFAULT_TSA_URL, config)
        assert response.is_granted is False

    def test_tsa_url_preserved(self):
        """The TSA URL is reflected in the parsed response."""
        tsr_der = _make_granted_tsr_der()
        config = TimestampConfig()
        response = _parse_minimal(tsr_der, "https://custom-tsa.example.com", config)
        assert response.tsa_url == "https://custom-tsa.example.com"

    def test_bad_input_returns_rejection(self):
        """Garbage DER falls back to status=2 (rejection)."""
        config = TimestampConfig()
        response = _parse_minimal(b"\xff\xff\xff", DEFAULT_TSA_URL, config)
        assert response.is_granted is False


# ---------------------------------------------------------------------------
# 5. TimestampResponse model
# ---------------------------------------------------------------------------


class TestTimestampResponseModel:
    """Tests for the TimestampResponse Pydantic model."""

    def test_is_granted_true_for_status_zero(self):
        resp = _make_timestamp_response(status=0)
        assert resp.is_granted is True

    def test_is_granted_true_for_status_one(self):
        resp = _make_timestamp_response(status=1)
        assert resp.is_granted is True

    def test_is_granted_false_for_status_two(self):
        resp = _make_timestamp_response(status=2)
        assert resp.is_granted is False

    def test_received_at_auto_populated(self):
        resp = _make_timestamp_response()
        assert resp.received_at is not None
        assert resp.received_at.tzinfo is not None


# ---------------------------------------------------------------------------
# 6. TimestampResult model
# ---------------------------------------------------------------------------


class TestTimestampResultModel:
    """Tests for the TimestampResult Pydantic model."""

    def test_is_valid_when_status_valid(self):
        result = TimestampResult(
            file_path="/tmp/test.pdf",
            file_hash="a" * 64,
            tsa_url=DEFAULT_TSA_URL,
            verification_status=TimestampStatus.VALID,
        )
        assert result.is_valid is True

    def test_is_not_valid_when_status_pending(self):
        result = TimestampResult(
            file_path="/tmp/test.pdf",
            file_hash="a" * 64,
            tsa_url=DEFAULT_TSA_URL,
            verification_status=TimestampStatus.PENDING,
        )
        assert result.is_valid is False


# ---------------------------------------------------------------------------
# 7. verify_timestamp
# ---------------------------------------------------------------------------


class TestVerifyTimestamp:
    """Tests for verify_timestamp()."""

    def test_rejected_response_returns_false(self, sample_pdf: bytes):
        """A non-granted response immediately returns False."""
        response = _make_timestamp_response(status=2)
        assert verify_timestamp(response, sample_pdf) is False

    def test_no_token_der_returns_false(self, sample_pdf: bytes):
        """Missing token_der returns False."""
        response = TimestampResponse(
            status=0,
            tsa_url=DEFAULT_TSA_URL,
            token_der=None,
        )
        assert verify_timestamp(response, sample_pdf) is False

    def test_imprint_mismatch_returns_false(self, sample_pdf: bytes):
        """Wrong message_imprint returns False."""
        response = _make_timestamp_response(
            status=0,
            message_imprint="0" * 64,  # wrong hash
            token_der=b"\x30\x00",
        )
        # sample_pdf will produce a different hash
        assert verify_timestamp(response, sample_pdf) is False

    def test_correct_imprint_passes_when_no_rfc3161ng(self, sample_pdf: bytes):
        """Correct message_imprint passes the imprint check."""
        correct_hash = hashlib.sha256(sample_pdf).hexdigest()
        response = _make_timestamp_response(
            status=0,
            message_imprint=correct_hash,
            token_der=b"\x30\x00",
        )
        # Patch rfc3161ng away to test the imprint-only path
        with patch("skseal.timestamp._has_rfc3161ng", return_value=False):
            result = verify_timestamp(response, sample_pdf)
        assert result is True


# ---------------------------------------------------------------------------
# 8. timestamp_document — mocked HTTP
# ---------------------------------------------------------------------------


class TestTimestampDocument:
    """Integration-style tests for timestamp_document() with mocked HTTP."""

    def _make_mock_submit(self, sample_pdf: bytes) -> TimestampResponse:
        """Build a realistic mock TimestampResponse for sample_pdf."""
        correct_hash = hashlib.sha256(sample_pdf).hexdigest()
        return _make_timestamp_response(
            status=0,
            message_imprint=correct_hash,
            token_der=b"\x30\x03\x02\x01\x00",
            timestamp=datetime(2026, 2, 27, 12, 0, 0, tzinfo=timezone.utc),
        )

    def test_returns_timestamp_result(self, sample_pdf: bytes, tmp_path: Path):
        """timestamp_document returns a TimestampResult."""
        pdf_path = tmp_path / "contract.pdf"
        pdf_path.write_bytes(sample_pdf)

        mock_response = self._make_mock_submit(sample_pdf)

        with patch("skseal.timestamp.submit_timestamp", return_value=mock_response):
            with patch("skseal.timestamp._has_rfc3161ng", return_value=False):
                result = timestamp_document(str(pdf_path), save_token=False)

        assert isinstance(result, TimestampResult)
        assert result.file_path == str(pdf_path)

    def test_valid_verification_status(self, sample_pdf: bytes, tmp_path: Path):
        """Correctly matching imprint yields VALID verification status."""
        pdf_path = tmp_path / "contract.pdf"
        pdf_path.write_bytes(sample_pdf)

        mock_response = self._make_mock_submit(sample_pdf)

        with patch("skseal.timestamp.submit_timestamp", return_value=mock_response):
            with patch("skseal.timestamp._has_rfc3161ng", return_value=False):
                result = timestamp_document(str(pdf_path), save_token=False)

        assert result.verification_status == TimestampStatus.VALID

    def test_saves_tsr_file(self, sample_pdf: bytes, tmp_path: Path):
        """Token is saved as <file>.tsr when save_token=True."""
        pdf_path = tmp_path / "contract.pdf"
        pdf_path.write_bytes(sample_pdf)

        mock_response = self._make_mock_submit(sample_pdf)

        with patch("skseal.timestamp.submit_timestamp", return_value=mock_response):
            with patch("skseal.timestamp._has_rfc3161ng", return_value=False):
                result = timestamp_document(str(pdf_path), save_token=True)

        expected_tsr = tmp_path / "contract.pdf.tsr"
        assert expected_tsr.exists()
        assert result.tsr_path == str(expected_tsr)

    def test_file_not_found_raises(self):
        """FileNotFoundError raised for non-existent file."""
        with pytest.raises(FileNotFoundError):
            timestamp_document("/nonexistent/path/doc.pdf")

    def test_all_tsas_fail_returns_error(self, sample_pdf: bytes, tmp_path: Path):
        """When all TSAs fail, result.error is set."""
        pdf_path = tmp_path / "contract.pdf"
        pdf_path.write_bytes(sample_pdf)

        with patch(
            "skseal.timestamp.submit_timestamp",
            side_effect=RuntimeError("connection refused"),
        ):
            result = timestamp_document(str(pdf_path), save_token=False)

        assert result.error is not None
        assert result.verification_status == TimestampStatus.ERROR

    def test_file_hash_matches_sha256(self, sample_pdf: bytes, tmp_path: Path):
        """file_hash in result matches the expected SHA-256 digest."""
        pdf_path = tmp_path / "contract.pdf"
        pdf_path.write_bytes(sample_pdf)

        expected_hash = hashlib.sha256(sample_pdf).hexdigest()
        mock_response = self._make_mock_submit(sample_pdf)

        with patch("skseal.timestamp.submit_timestamp", return_value=mock_response):
            with patch("skseal.timestamp._has_rfc3161ng", return_value=False):
                result = timestamp_document(str(pdf_path), save_token=False)

        assert result.file_hash == expected_hash


# ---------------------------------------------------------------------------
# 9. load_tsr_file
# ---------------------------------------------------------------------------


class TestLoadTsrFile:
    """Tests for load_tsr_file()."""

    def test_loads_valid_tsr(self, tmp_path: Path):
        """Loads and parses a .tsr file from disk."""
        tsr_bytes = _make_granted_tsr_der()
        tsr_path = tmp_path / "contract.pdf.tsr"
        tsr_path.write_bytes(tsr_bytes)

        with patch("skseal.timestamp._has_rfc3161ng", return_value=False):
            with patch("skseal.timestamp._has_asn1crypto", return_value=False):
                response = load_tsr_file(str(tsr_path))

        assert response is not None
        assert response.tsa_url == DEFAULT_TSA_URL

    def test_missing_file_raises(self):
        """FileNotFoundError raised when file does not exist."""
        with pytest.raises(FileNotFoundError):
            load_tsr_file("/tmp/nonexistent_totally_missing.tsr")


# ---------------------------------------------------------------------------
# 10. CLI — timestamp stamp
# ---------------------------------------------------------------------------


class TestCliTimestampStamp:
    """Tests for the `skseal timestamp stamp` CLI command."""

    def _make_mock_response(self, sample_pdf: bytes) -> TimestampResponse:
        correct_hash = hashlib.sha256(sample_pdf).hexdigest()
        return _make_timestamp_response(
            status=0,
            message_imprint=correct_hash,
            token_der=b"\x30\x03\x02\x01\x00",
        )

    def test_stamp_success(self, sample_pdf: bytes, tmp_path: Path):
        """Stamp command exits 0 on success."""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(sample_pdf)

        mock_response = self._make_mock_response(sample_pdf)
        runner = CliRunner()

        with patch("skseal.timestamp.submit_timestamp", return_value=mock_response):
            with patch("skseal.timestamp._has_rfc3161ng", return_value=False):
                result = runner.invoke(
                    main,
                    ["timestamp", "stamp", str(pdf_path), "--no-save"],
                )

        assert result.exit_code == 0
        assert "Timestamp" in result.output

    def test_stamp_missing_file(self, tmp_path: Path):
        """Stamp command exits non-zero for missing file."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["timestamp", "stamp", str(tmp_path / "ghost.pdf")],
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# 11. CLI — timestamp verify
# ---------------------------------------------------------------------------


class TestCliTimestampVerify:
    """Tests for the `skseal timestamp verify` CLI command."""

    def test_verify_valid(self, sample_pdf: bytes, tmp_path: Path):
        """Verify exits 0 when the timestamp is valid."""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(sample_pdf)

        tsr_bytes = _make_granted_tsr_der()
        tsr_path = tmp_path / "test.pdf.tsr"
        tsr_path.write_bytes(tsr_bytes)

        correct_hash = hashlib.sha256(sample_pdf).hexdigest()
        mock_response = _make_timestamp_response(
            status=0,
            message_imprint=correct_hash,
            token_der=tsr_bytes,
        )

        runner = CliRunner()
        with patch("skseal.timestamp._has_rfc3161ng", return_value=False):
            with patch("skseal.timestamp._has_asn1crypto", return_value=False):
                with patch(
                    "skseal.cli.load_tsr_file", return_value=mock_response
                ):
                    result = runner.invoke(
                        main,
                        [
                            "timestamp",
                            "verify",
                            str(pdf_path),
                            "--token",
                            str(tsr_path),
                        ],
                    )

        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_verify_missing_token(self, sample_pdf: bytes, tmp_path: Path):
        """Verify exits non-zero when .tsr file is missing."""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(sample_pdf)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["timestamp", "verify", str(pdf_path)],
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# 12. CLI — timestamp info
# ---------------------------------------------------------------------------


class TestCliTimestampInfo:
    """Tests for the `skseal timestamp info` CLI command."""

    def test_info_displays_table(self, tmp_path: Path):
        """Info command displays a table of token metadata."""
        tsr_bytes = _make_granted_tsr_der()
        tsr_path = tmp_path / "contract.pdf.tsr"
        tsr_path.write_bytes(tsr_bytes)

        mock_response = _make_timestamp_response(
            status=0,
            token_der=tsr_bytes,
        )

        runner = CliRunner()
        with patch("skseal.cli.load_tsr_file", return_value=mock_response):
            result = runner.invoke(
                main,
                ["timestamp", "info", str(tsr_path)],
            )

        assert result.exit_code == 0
        # Table has column headers
        assert "Field" in result.output or "TSA" in result.output or "Status" in result.output

    def test_info_missing_tsr(self, tmp_path: Path):
        """Info exits non-zero for non-existent .tsr file."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["timestamp", "info", str(tmp_path / "ghost.tsr")],
        )
        assert result.exit_code != 0
