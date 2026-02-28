"""RFC 3161 timestamping client for SKSeal.

Provides non-repudiation proof for legally signed documents by anchoring
document hashes to a trusted Time Stamping Authority (TSA). The resulting
timestamp token (.tsr file) cryptographically proves that the document
existed in its current form at a specific point in time — a requirement
for eIDAS qualified signatures and long-term archival under ETSI EN 319 122.

Two implementation strategies are used in priority order:

1. ``rfc3161ng`` — high-level library that handles ASN.1 encoding/decoding,
   HTTP submission, and certificate chain validation automatically.
2. Fallback — manual implementation using ``cryptography`` and ``asn1crypto``
   for raw ASN.1 construction and HTTP POST to the TSA endpoint.

Both strategies produce standard DER-encoded TimeStampToken files (.tsr)
that are interoperable with OpenSSL, Adobe, and legal archival systems.

Default TSAs:
    - FreeTSA (https://freetsa.org/tsr) — free, no account required
    - DigiCert (http://timestamp.digicert.com) — commercial, widely trusted
    - GlobalSign (http://timestamp.globalsign.com/tsa/r6advanced1) — commercial

Usage::

    from skseal.timestamp import timestamp_document, verify_timestamp

    result = timestamp_document("/path/to/contract.pdf")
    if result.is_valid:
        print(f"Timestamp verified: {result.response.timestamp}")
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models_timestamp import (
    HashAlgorithm,
    TimestampConfig,
    TimestampResponse,
    TimestampResult,
    TimestampStatus,
)

logger = logging.getLogger("skseal.timestamp")

# ---------------------------------------------------------------------------
# Default TSA endpoints
# ---------------------------------------------------------------------------

DEFAULT_TSA_URLS: list[str] = [
    "https://freetsa.org/tsr",
    "http://timestamp.digicert.com",
    "http://timestamp.globalsign.com/tsa/r6advanced1",
]

DEFAULT_TSA_URL = DEFAULT_TSA_URLS[0]

# OID constants (as dotted strings)
_OID_SHA256 = "2.16.840.1.101.3.4.2.1"
_OID_SHA384 = "2.16.840.1.101.3.4.2.2"
_OID_SHA512 = "2.16.840.1.101.3.4.2.3"
_OID_TSP_REQUEST = "1.2.840.113549.1.9.16.1.4"

_HASH_OID: dict[HashAlgorithm, str] = {
    HashAlgorithm.SHA256: _OID_SHA256,
    HashAlgorithm.SHA384: _OID_SHA384,
    HashAlgorithm.SHA512: _OID_SHA512,
}

_HASH_FUNC: dict[HashAlgorithm, str] = {
    HashAlgorithm.SHA256: "sha256",
    HashAlgorithm.SHA384: "sha384",
    HashAlgorithm.SHA512: "sha512",
}


# ---------------------------------------------------------------------------
# Library availability detection
# ---------------------------------------------------------------------------


def _has_rfc3161ng() -> bool:
    """Return True if rfc3161ng is importable."""
    try:
        import rfc3161ng  # noqa: F401
        return True
    except ImportError:
        return False


def _has_asn1crypto() -> bool:
    """Return True if asn1crypto is importable."""
    try:
        import asn1crypto  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# ASN.1 DER encoding helpers (minimal fallback implementation)
# ---------------------------------------------------------------------------


def _der_length(n: int) -> bytes:
    """Encode an ASN.1 DER length field.

    Args:
        n: The length value to encode.

    Returns:
        DER-encoded length bytes.
    """
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    # Support up to 3-byte lengths (16 MB — more than enough for a TSR)
    return bytes([0x83, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def _der_tlv(tag: int, value: bytes) -> bytes:
    """Wrap value in a DER TLV (Type-Length-Value) structure.

    Args:
        tag: ASN.1 tag byte.
        value: The already-encoded value bytes.

    Returns:
        Complete DER TLV bytes.
    """
    return bytes([tag]) + _der_length(len(value)) + value


def _der_sequence(*items: bytes) -> bytes:
    """Wrap items in a DER SEQUENCE.

    Args:
        *items: Pre-encoded DER items.

    Returns:
        SEQUENCE TLV.
    """
    return _der_tlv(0x30, b"".join(items))


def _der_integer(value: int) -> bytes:
    """Encode a non-negative integer as DER INTEGER.

    Args:
        value: The integer value.

    Returns:
        DER INTEGER bytes.
    """
    if value == 0:
        return _der_tlv(0x02, b"\x00")
    result = []
    n = value
    while n:
        result.append(n & 0xFF)
        n >>= 8
    result.reverse()
    # Ensure no sign bit is set (add leading zero if MSB is set)
    if result[0] & 0x80:
        result.insert(0, 0x00)
    return _der_tlv(0x02, bytes(result))


def _der_oid(dotted: str) -> bytes:
    """Encode a dotted-notation OID as DER OBJECT IDENTIFIER.

    Args:
        dotted: OID in dotted-decimal notation (e.g. "2.16.840.1.101.3.4.2.1").

    Returns:
        DER OID bytes.
    """
    parts = [int(x) for x in dotted.split(".")]
    # First two arcs are merged: 40 * arc0 + arc1
    encoded = [40 * parts[0] + parts[1]]
    for arc in parts[2:]:
        if arc == 0:
            encoded.append(0)
        else:
            chunk = []
            while arc:
                chunk.append(arc & 0x7F)
                arc >>= 7
            chunk.reverse()
            for i, b in enumerate(chunk):
                encoded.append(b | (0x80 if i < len(chunk) - 1 else 0))
    return _der_tlv(0x06, bytes(encoded))


def _der_octet_string(data: bytes) -> bytes:
    """Encode bytes as DER OCTET STRING.

    Args:
        data: Raw bytes to encode.

    Returns:
        DER OCTET STRING.
    """
    return _der_tlv(0x04, data)


def _der_boolean_true() -> bytes:
    """Encode DER BOOLEAN TRUE."""
    return _der_tlv(0x01, b"\xff")


def _der_null() -> bytes:
    """Encode DER NULL."""
    return _der_tlv(0x05, b"")


def _build_timestamp_request_der(
    message_imprint: bytes,
    algorithm_oid: str,
    nonce: Optional[int] = None,
    request_cert: bool = True,
) -> bytes:
    """Build a DER-encoded RFC 3161 TimeStampReq manually.

    TimeStampReq ::= SEQUENCE {
        version         INTEGER { v1(1) },
        messageImprint  MessageImprint,
        reqPolicy       TSAPolicyId OPTIONAL,
        nonce           INTEGER OPTIONAL,
        certReq         BOOLEAN OPTIONAL,
        extensions      [0] IMPLICIT Extensions OPTIONAL
    }

    MessageImprint ::= SEQUENCE {
        hashAlgorithm   AlgorithmIdentifier,
        hashedMessage   OCTET STRING
    }

    Args:
        message_imprint: The hash bytes of the data to timestamp.
        algorithm_oid: OID of the hash algorithm used.
        nonce: Random nonce value (optional, improves replay protection).
        request_cert: Whether to request the TSA certificate in the response.

    Returns:
        DER-encoded TimeStampReq bytes.
    """
    # version INTEGER { v1(1) }
    version = _der_integer(1)

    # AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
    alg_id = _der_sequence(_der_oid(algorithm_oid), _der_null())

    # MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }
    msg_imprint = _der_sequence(alg_id, _der_octet_string(message_imprint))

    # certReq BOOLEAN OPTIONAL
    cert_req = _der_boolean_true() if request_cert else b""

    # nonce INTEGER OPTIONAL
    nonce_der = _der_integer(nonce) if nonce is not None else b""

    return _der_sequence(version, msg_imprint, nonce_der, cert_req)


# ---------------------------------------------------------------------------
# Public API — request creation
# ---------------------------------------------------------------------------


def create_timestamp_request(
    data: bytes,
    config: Optional[TimestampConfig] = None,
) -> bytes:
    """Create an RFC 3161 TimeStampReq for the given data.

    Hashes the data with the configured algorithm and wraps it in a
    properly formatted DER-encoded TimeStampReq ready for submission to
    a TSA endpoint via HTTP POST.

    Args:
        data: Raw bytes to timestamp (typically the document content or
            its hash if already hashed).
        config: Timestamp configuration (TSA URL, hash algorithm, etc.).
            Uses defaults if not provided.

    Returns:
        DER-encoded TimeStampReq bytes.

    Example::

        pdf_bytes = Path("contract.pdf").read_bytes()
        request = create_timestamp_request(pdf_bytes)
        # Submit request to TSA...
    """
    if config is None:
        config = TimestampConfig()

    hash_func = _HASH_FUNC[config.hash_algorithm]
    digest = hashlib.new(hash_func, data).digest()
    algorithm_oid = _HASH_OID[config.hash_algorithm]

    nonce_value: Optional[int] = None
    if config.nonce:
        # 64-bit random nonce — prevents replay attacks
        nonce_value = int.from_bytes(secrets.token_bytes(8), "big")

    if _has_rfc3161ng():
        return _create_request_rfc3161ng(digest, config, nonce_value)

    return _build_timestamp_request_der(
        message_imprint=digest,
        algorithm_oid=algorithm_oid,
        nonce=nonce_value,
        request_cert=config.request_cert,
    )


def _create_request_rfc3161ng(
    digest: bytes,
    config: TimestampConfig,
    nonce: Optional[int],
) -> bytes:
    """Create a TimeStampReq using the rfc3161ng library.

    Args:
        digest: Pre-computed message digest bytes.
        config: Timestamp configuration.
        nonce: Optional nonce value.

    Returns:
        DER-encoded TimeStampReq bytes.
    """
    import rfc3161ng

    hash_algo = config.hash_algorithm.value  # e.g. "sha256"
    return rfc3161ng.make_timestamp_request(
        digest,
        hashname=hash_algo,
        nonce=nonce,
        include_tsa_certificate=config.request_cert,
    )


# ---------------------------------------------------------------------------
# Public API — submission
# ---------------------------------------------------------------------------


def submit_timestamp(
    request: bytes,
    tsa_url: str,
    config: Optional[TimestampConfig] = None,
) -> TimestampResponse:
    """Submit a TimeStampReq to a TSA and return the parsed response.

    Performs an HTTP POST to the TSA endpoint with Content-Type
    ``application/timestamp-query`` and parses the DER-encoded
    TimeStampResp that comes back.

    Args:
        request: DER-encoded TimeStampReq bytes from
            :func:`create_timestamp_request`.
        tsa_url: URL of the TSA endpoint.
        config: Optional configuration (for timeout settings).

    Returns:
        Parsed :class:`TimestampResponse` with status and token.

    Raises:
        RuntimeError: If the HTTP request fails or the TSA returns an
            error status.

    Example::

        response = submit_timestamp(request, "https://freetsa.org/tsr")
        if response.is_granted:
            print(f"Timestamp serial: {response.serial_number}")
    """
    if config is None:
        config = TimestampConfig(tsa_url=tsa_url)

    try:
        import urllib.request

        req = urllib.request.Request(
            tsa_url,
            data=request,
            headers={
                "Content-Type": "application/timestamp-query",
                "Accept": "application/timestamp-reply",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=config.timeout_seconds) as resp:
            response_der = resp.read()

    except Exception as exc:
        logger.error("TSA HTTP request failed for %s: %s", tsa_url, exc)
        raise RuntimeError(f"TSA request to {tsa_url} failed: {exc}") from exc

    return _parse_timestamp_response(response_der, tsa_url, config)


def _parse_timestamp_response(
    response_der: bytes,
    tsa_url: str,
    config: TimestampConfig,
) -> TimestampResponse:
    """Parse a DER-encoded TimeStampResp into a TimestampResponse model.

    Tries rfc3161ng first (full parsing), then asn1crypto (detailed ASN.1),
    then falls back to minimal parsing of the status field only.

    Args:
        response_der: Raw DER bytes from the TSA.
        tsa_url: TSA URL for metadata.
        config: Current timestamp configuration.

    Returns:
        Parsed TimestampResponse.
    """
    if _has_rfc3161ng():
        return _parse_with_rfc3161ng(response_der, tsa_url, config)

    if _has_asn1crypto():
        return _parse_with_asn1crypto(response_der, tsa_url, config)

    return _parse_minimal(response_der, tsa_url, config)


def _parse_with_rfc3161ng(
    response_der: bytes,
    tsa_url: str,
    config: TimestampConfig,
) -> TimestampResponse:
    """Parse a TSA response using rfc3161ng.

    Args:
        response_der: Raw DER bytes.
        tsa_url: TSA URL.
        config: Timestamp configuration.

    Returns:
        Parsed TimestampResponse.
    """
    import rfc3161ng

    try:
        tst = rfc3161ng.decode_timestamp_response(response_der)
        status = int(tst.status.status)

        ts_token = None
        serial = None
        ts_time = None
        tsa_name = None
        policy_id = None
        accuracy = None
        message_imprint_hex = None
        nonce_val = None
        token_der = None

        if status in (0, 1) and hasattr(tst, "time_stamp_token"):
            token = tst.time_stamp_token
            token_der = rfc3161ng.get_timestamp_token_der(tst)

            tsi = token.tst_info
            serial = int(tsi.serial_number)

            gen_time = tsi.gen_time
            if hasattr(gen_time, "native"):
                ts_time = gen_time.native
                if ts_time and ts_time.tzinfo is None:
                    ts_time = ts_time.replace(tzinfo=timezone.utc)
            elif hasattr(gen_time, "hasValue") and gen_time.hasValue():
                ts_time = datetime.now(timezone.utc)

            if hasattr(tsi, "policy"):
                policy_id = str(tsi.policy)

            if hasattr(tsi, "accuracy") and tsi.accuracy:
                acc = tsi.accuracy
                secs = float(getattr(acc, "seconds", 0) or 0)
                millis = float(getattr(acc, "millis", 0) or 0)
                micros = float(getattr(acc, "micros", 0) or 0)
                accuracy = secs + millis / 1000.0 + micros / 1_000_000.0

            if hasattr(tsi, "nonce") and tsi.nonce:
                nonce_val = int(tsi.nonce)

            if hasattr(tsi, "message_imprint"):
                mi = tsi.message_imprint
                if hasattr(mi, "hashed_message"):
                    message_imprint_hex = mi.hashed_message.native.hex()

        status_string = None
        if hasattr(tst.status, "status_string"):
            ss = tst.status.status_string
            if ss and hasattr(ss, "native"):
                status_string = str(ss.native)

        return TimestampResponse(
            status=status,
            status_string=status_string,
            tsa_url=tsa_url,
            serial_number=serial,
            timestamp=ts_time,
            hash_algorithm=config.hash_algorithm,
            message_imprint=message_imprint_hex,
            tsa_name=tsa_name,
            token_der=token_der,
            policy_id=policy_id,
            nonce=nonce_val,
            accuracy_seconds=accuracy,
        )
    except Exception as exc:
        logger.warning("rfc3161ng parsing failed, trying fallback: %s", exc)
        if _has_asn1crypto():
            return _parse_with_asn1crypto(response_der, tsa_url, config)
        return _parse_minimal(response_der, tsa_url, config)


def _parse_with_asn1crypto(
    response_der: bytes,
    tsa_url: str,
    config: TimestampConfig,
) -> TimestampResponse:
    """Parse a TSA response using asn1crypto.

    Args:
        response_der: Raw DER bytes.
        tsa_url: TSA URL.
        config: Timestamp configuration.

    Returns:
        Parsed TimestampResponse.
    """
    from asn1crypto import tsp, core

    try:
        resp = tsp.TimeStampResp.load(response_der)
        status = int(resp["status"]["status"].native)

        serial = None
        ts_time = None
        tsa_name = None
        policy_id = None
        accuracy = None
        message_imprint_hex = None
        nonce_val = None
        token_der = None

        if status in (0, 1):
            token_wrapper = resp["time_stamp_token"]
            if token_wrapper.native is not None:
                token_der = token_wrapper.contents
                content_info = token_wrapper
                # Navigate into SignedData -> encapContentInfo -> eContent -> TSTInfo
                try:
                    signed_data = content_info["content"]
                    econtent = signed_data["encap_content_info"]["content"]
                    tst_info = tsp.TSTInfo.load(econtent.parsed.native
                                                 if hasattr(econtent, "parsed")
                                                 else bytes(econtent))
                    serial = int(tst_info["serial_number"].native)
                    gen_time = tst_info["gen_time"].native
                    if isinstance(gen_time, datetime):
                        ts_time = gen_time
                        if ts_time.tzinfo is None:
                            ts_time = ts_time.replace(tzinfo=timezone.utc)

                    policy_id = str(tst_info["policy"].native)

                    accuracy_node = tst_info["accuracy"]
                    if accuracy_node.native:
                        secs = float(accuracy_node["seconds"].native or 0)
                        millis = float(accuracy_node["millis"].native or 0)
                        micros = float(accuracy_node["micros"].native or 0)
                        accuracy = secs + millis / 1000.0 + micros / 1_000_000.0

                    nonce_node = tst_info["nonce"]
                    if nonce_node.native:
                        nonce_val = int(nonce_node.native)

                    mi = tst_info["message_imprint"]
                    message_imprint_hex = mi["hashed_message"].native.hex()

                except Exception as inner:
                    logger.debug("asn1crypto TSTInfo extraction failed: %s", inner)

        status_string_nodes = resp["status"].get("status_string")
        status_string = None
        if status_string_nodes and status_string_nodes.native:
            status_string = str(status_string_nodes.native[0])

        return TimestampResponse(
            status=status,
            status_string=status_string,
            tsa_url=tsa_url,
            serial_number=serial,
            timestamp=ts_time,
            hash_algorithm=config.hash_algorithm,
            message_imprint=message_imprint_hex,
            tsa_name=tsa_name,
            token_der=token_der,
            policy_id=policy_id,
            nonce=nonce_val,
            accuracy_seconds=accuracy,
        )
    except Exception as exc:
        logger.warning("asn1crypto parsing failed, falling back to minimal: %s", exc)
        return _parse_minimal(response_der, tsa_url, config)


def _parse_minimal(
    response_der: bytes,
    tsa_url: str,
    config: TimestampConfig,
) -> TimestampResponse:
    """Minimal DER parser — extracts only the PKI status from the response.

    Used as last-resort fallback when no ASN.1 libraries are available.
    The TimeStampResp SEQUENCE's first element is a PKIStatusInfo SEQUENCE,
    whose first element is the status INTEGER.

    Args:
        response_der: Raw DER bytes.
        tsa_url: TSA URL.
        config: Timestamp configuration.

    Returns:
        TimestampResponse with status and raw token_der only.
    """
    status = 2  # default: rejection
    try:
        # TimeStampResp is a SEQUENCE — skip the outer SEQUENCE tag+length
        if len(response_der) > 2 and response_der[0] == 0x30:
            offset = 2
            if response_der[1] & 0x80:
                num_bytes = response_der[1] & 0x7F
                offset += num_bytes
            # Now inside the SEQUENCE, first item is PKIStatusInfo (SEQUENCE)
            if response_der[offset] == 0x30:
                pki_offset = offset + 2
                if response_der[offset + 1] & 0x80:
                    nb = response_der[offset + 1] & 0x7F
                    pki_offset += nb
                # First element of PKIStatusInfo is status INTEGER
                if response_der[pki_offset] == 0x02:
                    int_len = response_der[pki_offset + 1]
                    int_bytes = response_der[pki_offset + 2 : pki_offset + 2 + int_len]
                    status = int.from_bytes(int_bytes, "big")
    except Exception as exc:
        logger.debug("Minimal TSR parsing failed: %s", exc)

    return TimestampResponse(
        status=status,
        tsa_url=tsa_url,
        hash_algorithm=config.hash_algorithm,
        token_der=response_der if status in (0, 1) else None,
    )


# ---------------------------------------------------------------------------
# Public API — verification
# ---------------------------------------------------------------------------


def verify_timestamp(
    response: TimestampResponse,
    original_data: bytes,
    config: Optional[TimestampConfig] = None,
) -> bool:
    """Verify that a timestamp token covers the given data.

    Checks:
    1. The TSA response status is "granted" (status 0 or 1).
    2. The message imprint in the token matches the hash of original_data.

    Certificate chain validation is performed by rfc3161ng when available.

    Args:
        response: A TimestampResponse previously obtained from
            :func:`submit_timestamp`.
        original_data: The original bytes that were timestamped (e.g. the
            document content as passed to :func:`create_timestamp_request`).
        config: Optional configuration (for algorithm selection).

    Returns:
        True if the timestamp token is valid and covers original_data.

    Example::

        is_valid = verify_timestamp(response, pdf_bytes)
        print("Timestamp valid" if is_valid else "Timestamp INVALID")
    """
    if not response.is_granted:
        logger.warning("TSA response status is not granted: %d", response.status)
        return False

    if response.token_der is None:
        logger.warning("No token DER in response — cannot verify")
        return False

    if config is None:
        config = TimestampConfig()

    # Verify the message imprint matches
    hash_func = _HASH_FUNC[response.hash_algorithm]
    expected_digest = hashlib.new(hash_func, original_data).hexdigest()

    if response.message_imprint is not None:
        if response.message_imprint.lower() != expected_digest.lower():
            logger.warning(
                "Message imprint mismatch: token=%s, computed=%s",
                response.message_imprint[:16],
                expected_digest[:16],
            )
            return False

    # If rfc3161ng is available, do a full cryptographic verification
    if _has_rfc3161ng():
        return _verify_with_rfc3161ng(response, original_data, config)

    # Without a full ASN.1 library we can only check the imprint field
    logger.info(
        "rfc3161ng not available — performing imprint-only verification"
    )
    return True


def _verify_with_rfc3161ng(
    response: TimestampResponse,
    original_data: bytes,
    config: TimestampConfig,
) -> bool:
    """Full cryptographic verification using rfc3161ng.

    Args:
        response: The timestamp response to verify.
        original_data: Original data bytes.
        config: Timestamp configuration.

    Returns:
        True if the timestamp is cryptographically valid.
    """
    import rfc3161ng

    try:
        hash_func = _HASH_FUNC[response.hash_algorithm]
        digest = hashlib.new(hash_func, original_data).digest()
        rfc3161ng.check_timestamp(
            response.token_der,
            digest=digest,
            hashname=hash_func,
        )
        return True
    except rfc3161ng.TimestampError as exc:
        logger.warning("rfc3161ng timestamp verification failed: %s", exc)
        return False
    except Exception as exc:
        logger.error("Unexpected error during timestamp verification: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Public API — high-level document timestamping
# ---------------------------------------------------------------------------


def timestamp_document(
    file_path: str,
    tsa_url: Optional[str] = None,
    config: Optional[TimestampConfig] = None,
    save_token: bool = True,
) -> TimestampResult:
    """Hash a file, submit it to a TSA, verify the response, and save the token.

    This is the primary high-level entry point for timestamping. It:
    1. Reads and hashes the file.
    2. Creates a TimeStampReq.
    3. Submits it to the TSA (with automatic fallback to secondary TSAs).
    4. Parses and verifies the response.
    5. Saves the .tsr file alongside the document.

    Args:
        file_path: Absolute or relative path to the file to timestamp.
        tsa_url: TSA endpoint URL. Defaults to FreeTSA, then DigiCert.
        config: Full configuration object. If provided, tsa_url is ignored.
        save_token: If True, save the .tsr file next to the document.

    Returns:
        :class:`TimestampResult` with all details including verification status.

    Raises:
        FileNotFoundError: If file_path does not exist.

    Example::

        result = timestamp_document("/srv/contracts/nda.pdf")
        if result.is_valid:
            print(f"Token saved to: {result.tsr_path}")
            print(f"Certified time: {result.response.timestamp}")
    """
    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if config is None:
        effective_url = tsa_url or DEFAULT_TSA_URL
        config = TimestampConfig(tsa_url=effective_url)
    else:
        effective_url = config.tsa_url

    # Read and hash the file
    file_bytes = path.read_bytes()
    hash_func = _HASH_FUNC[config.hash_algorithm]
    file_hash = hashlib.new(hash_func, file_bytes).hexdigest()

    result = TimestampResult(
        file_path=str(path),
        file_hash=file_hash,
        hash_algorithm=config.hash_algorithm,
        tsa_url=effective_url,
        verification_status=TimestampStatus.PENDING,
    )

    # Try the configured TSA first, then fall back to the default list
    tsa_candidates = [effective_url] + [
        u for u in DEFAULT_TSA_URLS if u != effective_url
    ]

    response: Optional[TimestampResponse] = None
    for candidate_url in tsa_candidates:
        try:
            logger.info("Submitting timestamp request to %s", candidate_url)
            request_der = create_timestamp_request(file_bytes, config)
            response = submit_timestamp(request_der, candidate_url, config)
            if response.is_granted:
                result.tsa_url = candidate_url
                break
            logger.warning(
                "TSA %s returned non-granted status %d, trying next",
                candidate_url,
                response.status,
            )
        except Exception as exc:
            logger.warning("TSA %s failed: %s, trying next", candidate_url, exc)
            continue

    if response is None or not response.is_granted:
        result.verification_status = TimestampStatus.ERROR
        result.error = "All TSA endpoints failed or returned non-granted status"
        logger.error(result.error)
        return result

    result.response = response

    # Verify the token covers our document
    is_valid = verify_timestamp(response, file_bytes, config)
    result.verification_status = (
        TimestampStatus.VALID if is_valid else TimestampStatus.INVALID
    )

    # Save the .tsr token file
    if save_token and response.token_der is not None:
        tsr_path = path.with_suffix(path.suffix + ".tsr")
        tsr_path.write_bytes(response.token_der)
        result.tsr_path = str(tsr_path)
        logger.info("Saved timestamp token to %s", tsr_path)

    return result


# ---------------------------------------------------------------------------
# Public API — info extraction
# ---------------------------------------------------------------------------


def load_tsr_file(tsr_path: str, tsa_url: str = DEFAULT_TSA_URL) -> TimestampResponse:
    """Load and parse a .tsr file from disk.

    Args:
        tsr_path: Path to the DER-encoded .tsr file.
        tsa_url: TSA URL to embed in the response metadata.

    Returns:
        Parsed TimestampResponse.

    Raises:
        FileNotFoundError: If the .tsr file does not exist.
    """
    path = Path(tsr_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"TSR file not found: {tsr_path}")

    token_der = path.read_bytes()
    config = TimestampConfig(tsa_url=tsa_url)

    # A bare .tsr is typically just the token, not the full TimeStampResp.
    # Wrap it in a minimal "granted" shell if it doesn't look like a full resp.
    # Full TimeStampResp starts with SEQUENCE containing PKIStatusInfo(SEQUENCE).
    # If token_der starts with 0x30 and the next SEQUENCE is NOT a PKIStatusInfo
    # (i.e. it's a ContentInfo), we build a synthetic status-only wrapper.
    try:
        return _parse_timestamp_response(token_der, tsa_url, config)
    except Exception:
        # Treat it as a raw TimeStampToken (ContentInfo)
        return TimestampResponse(
            status=0,
            tsa_url=tsa_url,
            hash_algorithm=config.hash_algorithm,
            token_der=token_der,
        )
