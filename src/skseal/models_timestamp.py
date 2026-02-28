"""Pydantic models for RFC 3161 timestamping.

These models represent the data structures involved in Time Stamping Authority
(TSA) interactions: timestamp requests, responses, and verification results.
RFC 3161 timestamps provide non-repudiation proof by binding a document hash
to a trusted time source — a requirement for legally-binding document signing
in eIDAS, ESIGN Act, and similar regulatory frameworks.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class HashAlgorithm(str, Enum):
    """Hash algorithms supported for timestamp requests.

    SHA-256 is the default and widely accepted by TSAs. SHA-512 offers
    stronger security for high-assurance use cases.
    """

    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


class TimestampStatus(str, Enum):
    """Status of a timestamp operation."""

    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TimestampConfig(BaseModel):
    """Configuration for TSA connections and timestamp operations.

    Attributes:
        tsa_url: URL of the Time Stamping Authority endpoint.
        hash_algorithm: Hash algorithm to use for the timestamp request.
        cert_path: Optional path to TSA certificate for verification.
        timeout_seconds: HTTP request timeout in seconds.
        request_cert: Whether to request the TSA certificate in the response.
        nonce: Whether to include a random nonce in requests (prevents replay).
    """

    tsa_url: str = "https://freetsa.org/tsr"
    hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256
    cert_path: Optional[str] = None
    timeout_seconds: int = 30
    request_cert: bool = True
    nonce: bool = True

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# TSA Response
# ---------------------------------------------------------------------------


class TimestampResponse(BaseModel):
    """A parsed RFC 3161 TimeStampResp from a TSA.

    Represents the raw response from a Time Stamping Authority including
    the DER-encoded token and parsed metadata for quick inspection.

    Attributes:
        response_id: Unique identifier for this response record.
        status: PKI status code (0 = granted, 1 = granted with mods).
        status_string: Human-readable status message from TSA.
        tsa_url: The TSA endpoint that issued this response.
        serial_number: Unique serial assigned by the TSA to this timestamp.
        timestamp: The exact time certified by the TSA.
        hash_algorithm: Algorithm used to hash the data.
        message_imprint: Hex-encoded hash of the data that was timestamped.
        tsa_name: Distinguished name of the TSA that issued the token.
        token_der: Raw DER-encoded TimeStampToken bytes.
        policy_id: TSA policy OID under which the timestamp was issued.
        nonce: Nonce value echoed back by the TSA (if used).
        accuracy_seconds: Time accuracy claimed by the TSA in seconds.
        received_at: When this client received the response.
    """

    response_id: str = Field(default_factory=lambda: str(uuid4()))
    status: int
    status_string: Optional[str] = None
    tsa_url: str
    serial_number: Optional[int] = None
    timestamp: Optional[datetime] = None
    hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256
    message_imprint: Optional[str] = None
    tsa_name: Optional[str] = None
    token_der: Optional[bytes] = None
    policy_id: Optional[str] = None
    nonce: Optional[int] = None
    accuracy_seconds: Optional[float] = None
    received_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def is_granted(self) -> bool:
        """Return True if the TSA granted the timestamp request."""
        return self.status in (0, 1)

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Full result
# ---------------------------------------------------------------------------


class TimestampResult(BaseModel):
    """Complete result of a document timestamping operation.

    Bundles together the document identity, the hash that was timestamped,
    the TSA response, and the on-disk path where the token was saved.

    Attributes:
        result_id: Unique identifier.
        file_path: Absolute path to the file that was timestamped.
        file_hash: Hex-encoded hash of the file contents.
        hash_algorithm: Algorithm used to produce file_hash.
        tsa_url: TSA that issued the timestamp.
        tsr_path: Path to the saved .tsr file (DER-encoded token).
        response: The parsed TSA response.
        verification_status: Verification result (set after verify_timestamp).
        timestamped_at: When the operation was performed.
        error: Error message if the operation failed.
    """

    result_id: str = Field(default_factory=lambda: str(uuid4()))
    file_path: str
    file_hash: str
    hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256
    tsa_url: str
    tsr_path: Optional[str] = None
    response: Optional[TimestampResponse] = None
    verification_status: TimestampStatus = TimestampStatus.PENDING
    timestamped_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    error: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        """Return True if the timestamp has been verified as valid."""
        return self.verification_status == TimestampStatus.VALID

    model_config = {"populate_by_name": True}
