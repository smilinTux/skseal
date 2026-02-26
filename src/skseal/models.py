"""Core data models for SKSeal document signing.

Mirrors DocuSeal's JSON data model for template interchange but adds
sovereign superpowers: PGP signatures, Web of Trust identity, and
audit trails that live on your filesystem — not someone else's cloud.

Field coordinates use normalized (0-1) scale for resolution independence,
matching DocuSeal's approach so templates are portable across renderers.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FieldType(str, Enum):
    """Document field types — matches DocuSeal's 20 field types for
    template interchange compatibility, plus sovereign extensions."""

    HEADING = "heading"
    TEXT = "text"
    SIGNATURE = "signature"
    INITIALS = "initials"
    DATE = "date"
    DATENOW = "datenow"
    NUMBER = "number"
    IMAGE = "image"
    CHECKBOX = "checkbox"
    MULTIPLE = "multiple"
    FILE = "file"
    RADIO = "radio"
    SELECT = "select"
    CELLS = "cells"
    STAMP = "stamp"
    PAYMENT = "payment"
    PHONE = "phone"
    VERIFICATION = "verification"
    KBA = "kba"
    STRIKETHROUGH = "strikethrough"
    # Sovereign extensions
    PGP_SIGNATURE = "pgp_signature"
    FINGERPRINT = "fingerprint"


class DocumentStatus(str, Enum):
    """Lifecycle states for a signing document."""

    DRAFT = "draft"
    PENDING = "pending"
    PARTIALLY_SIGNED = "partially_signed"
    COMPLETED = "completed"
    VOIDED = "voided"
    EXPIRED = "expired"


class SignerRole(str, Enum):
    """Named roles that signers fill in a template."""

    SIGNER = "signer"
    COSIGNER = "cosigner"
    WITNESS = "witness"
    NOTARY = "notary"
    STEWARD = "steward"
    TRUSTEE = "trustee"


class SignerStatus(str, Enum):
    """Lifecycle states for an individual signer."""

    PENDING = "pending"
    VIEWED = "viewed"
    SIGNED = "signed"
    DECLINED = "declined"
    EXPIRED = "expired"


class AuditAction(str, Enum):
    """Actions recorded in the audit trail."""

    CREATED = "created"
    SENT = "sent"
    VIEWED = "viewed"
    FIELD_FILLED = "field_filled"
    SIGNED = "signed"
    DECLINED = "declined"
    VOIDED = "voided"
    COMPLETED = "completed"
    VERIFIED = "verified"
    DOWNLOADED = "downloaded"


# ---------------------------------------------------------------------------
# Field placement
# ---------------------------------------------------------------------------

class FieldPlacement(BaseModel):
    """Position of a field on a document page.

    Coordinates are normalized to 0-1 scale so the same template
    works at any resolution or zoom level. Format matches DocuSeal's
    ``areas`` JSON for template interchange.

    Attributes:
        page: 1-indexed page number (DocuSeal convention).
        x: Horizontal position (0.0 = left edge, 1.0 = right edge).
        y: Vertical position (0.0 = top edge, 1.0 = bottom edge).
        w: Field width as fraction of page width.
        h: Field height as fraction of page height.
    """

    page: int = 1
    x: float = 0.0
    y: float = 0.0
    w: float = 0.2
    h: float = 0.025


class FieldPreferences(BaseModel):
    """Visual preferences for a field — matches DocuSeal preferences block."""

    font_size: int = 12
    font_type: str = "normal"
    font: str = "Helvetica"
    color: str = "black"
    background: str = "white"
    align: str = "left"
    valign: str = "center"


class FieldValidation(BaseModel):
    """Validation rules for a field — matches DocuSeal validation block."""

    pattern: Optional[str] = None
    message: str = ""
    min_val: Optional[int] = Field(None, alias="min")
    max_val: Optional[int] = Field(None, alias="max")

    model_config = {"populate_by_name": True}


class DocumentField(BaseModel):
    """A single fillable field in a document.

    Follows DocuSeal's field JSON structure for template interchange,
    with sovereign extensions for PGP signature fields.

    Attributes:
        uuid: Unique identifier (DocuSeal calls this ``uuid``).
        name: Human-readable label (e.g. "Buyer Full Name").
        field_type: Type of field.
        role: Which signer role is responsible for this field.
        areas: Placement positions (a field can span multiple pages).
        required: Whether the field must be filled before completion.
        readonly: Whether the signer can modify the value.
        default_value: Pre-filled value (if any).
        options: Choices for dropdown/radio/select fields.
        title: Short display title.
        description: Help text shown to the signer.
        preferences: Visual rendering preferences.
        validation: Input validation rules.
    """

    uuid: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    field_type: FieldType = Field(FieldType.TEXT, alias="type")
    role: str = "Signer"
    areas: list[FieldPlacement] = Field(default_factory=list)
    required: bool = True
    readonly: bool = False
    default_value: Optional[str] = None
    options: list[str] = Field(default_factory=list)
    title: str = ""
    description: str = ""
    preferences: FieldPreferences = Field(default_factory=FieldPreferences)
    validation: Optional[FieldValidation] = None

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Signer
# ---------------------------------------------------------------------------

class Signer(BaseModel):
    """A party who must sign the document.

    Identity is PGP fingerprint — not email. The Web of Trust IS the
    identity layer. If you have their public key, you can verify their
    signature forever, offline, with zero platform dependency.

    Attributes:
        signer_id: Unique identifier for this signer instance.
        name: Display name.
        fingerprint: PGP fingerprint (40 hex chars). The sovereign identity.
        email: Optional contact email for notifications.
        role: Role this signer fills.
        status: Current signing status.
        public_key_armor: ASCII-armored PGP public key.
        signed_at: When the signer completed signing.
        declined_at: When the signer declined.
        decline_reason: Why they declined.
        viewing_key: One-time token for viewing the document (P2P delivery).
    """

    signer_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    fingerprint: str
    email: Optional[str] = None
    role: SignerRole = SignerRole.SIGNER
    status: SignerStatus = SignerStatus.PENDING
    public_key_armor: Optional[str] = None
    signed_at: Optional[datetime] = None
    declined_at: Optional[datetime] = None
    decline_reason: Optional[str] = None
    viewing_key: Optional[str] = None
    order: int = 0


# ---------------------------------------------------------------------------
# Signature record
# ---------------------------------------------------------------------------

class SignatureRecord(BaseModel):
    """Cryptographic proof that a signer signed specific content.

    This is the legally binding artifact. Contains the PGP detached
    signature over the document hash, the signer's identity, and
    metadata about when and how the signature was created.

    Attributes:
        record_id: Unique identifier.
        document_id: Which document was signed.
        signer_id: Which signer produced this signature.
        fingerprint: Signer's PGP fingerprint.
        document_hash: SHA-256 hash of the document bytes at signing time.
        signature_armor: ASCII-armored PGP signature.
        signed_at: Timestamp of signing.
        ip_address: IP at signing time (optional, for audit).
        user_agent: Browser/client info (optional, for audit).
        field_values: Values the signer filled in for their assigned fields.
    """

    record_id: str = Field(default_factory=lambda: str(uuid4()))
    document_id: str
    signer_id: str
    fingerprint: str
    document_hash: str
    signature_armor: str
    signed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    field_values: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------

class AuditEntry(BaseModel):
    """Immutable audit log entry for compliance and legal provenance.

    Attributes:
        entry_id: Unique identifier.
        document_id: Related document.
        action: What happened.
        actor_fingerprint: Who did it (PGP fingerprint).
        actor_name: Human-readable name.
        timestamp: When it happened.
        details: Free-form details about the action.
        ip_address: IP at the time of the action.
    """

    entry_id: str = Field(default_factory=lambda: str(uuid4()))
    document_id: str
    action: AuditAction
    actor_fingerprint: Optional[str] = None
    actor_name: Optional[str] = None
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    details: str = ""
    ip_address: Optional[str] = None


# ---------------------------------------------------------------------------
# Template
# ---------------------------------------------------------------------------

class TemplateDocument(BaseModel):
    """A PDF within a template — templates can contain multiple PDFs.

    Matches DocuSeal's ``documents`` array structure.

    Attributes:
        name: Display name for this document part.
        attachment_uuid: Reference to the stored PDF file.
        fields: Fields placed on this document.
    """

    name: str
    attachment_uuid: Optional[str] = None
    fields: list[DocumentField] = Field(default_factory=list)


class TemplateSubmitter(BaseModel):
    """A role slot in a template — filled by a real signer at send time.

    Matches DocuSeal's ``submitters`` array.

    Attributes:
        role: Named role (e.g. "Buyer", "Seller", "Witness").
        name: Default name (overridden when sending).
        email: Default email (overridden when sending).
        order: Signing order (0 = first).
    """

    role: str = "Signer"
    name: str = ""
    email: str = ""
    order: int = 0


class TemplateSettings(BaseModel):
    """Template-level settings for signing behavior."""

    expire_after_days: int = 30
    reminder_days: int = 7
    allow_decline: bool = True
    allow_forwarding: bool = False
    sequential_signing: bool = True


class Template(BaseModel):
    """Reusable document template with field placements.

    JSON structure is DocuSeal-compatible for template interchange,
    with sovereign extensions (PGP fields, trust requirements).

    Attributes:
        template_id: Unique identifier.
        name: Template name (e.g. "NDA", "Operating Agreement").
        external_id: External reference ID for integrations.
        folder_name: Organizational folder.
        description: What this template is for.
        documents: PDF documents with their field placements.
        submitters: Role slots that signers fill.
        settings: Signing behavior configuration.
        created_at: When the template was created.
        created_by: PGP fingerprint of the creator.
        tags: Organizational tags.
        version: Template version for tracking changes.
    """

    template_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    external_id: Optional[str] = None
    folder_name: str = ""
    description: str = ""
    documents: list[TemplateDocument] = Field(default_factory=list)
    submitters: list[TemplateSubmitter] = Field(default_factory=list)
    settings: TemplateSettings = Field(default_factory=TemplateSettings)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    created_by: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    version: int = 1


# ---------------------------------------------------------------------------
# Document (the main entity)
# ---------------------------------------------------------------------------

class Document(BaseModel):
    """A document in the signing workflow.

    The central entity tying together a PDF, signers, fields, signatures,
    and an audit trail. Documents are created from templates or ad-hoc.

    Attributes:
        document_id: Unique identifier.
        title: Human-readable title.
        description: What this document is about.
        status: Current lifecycle status.
        template_id: Template this was created from (if any).
        pdf_path: Path to the source PDF file.
        pdf_hash: SHA-256 hash of the original PDF.
        fields: Field definitions (copied from template or custom).
        signers: Parties who must sign.
        signatures: Completed signature records.
        audit_trail: Chronological event log.
        created_at: Creation timestamp.
        created_by: PGP fingerprint of the document creator.
        completed_at: When all signers finished.
        expires_at: Deadline for signing.
        metadata: Arbitrary key-value metadata.
    """

    document_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str = ""
    status: DocumentStatus = DocumentStatus.DRAFT
    template_id: Optional[str] = None
    pdf_path: Optional[str] = None
    pdf_hash: Optional[str] = None
    fields: list[DocumentField] = Field(default_factory=list)
    signers: list[Signer] = Field(default_factory=list)
    signatures: list[SignatureRecord] = Field(default_factory=list)
    audit_trail: list[AuditEntry] = Field(default_factory=list)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    created_by: Optional[str] = None
    completed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    metadata: dict[str, str] = Field(default_factory=dict)

    @property
    def is_complete(self) -> bool:
        """All signers have signed."""
        return all(s.status == SignerStatus.SIGNED for s in self.signers)

    @property
    def pending_signers(self) -> list[Signer]:
        """Signers who haven't signed yet."""
        return [s for s in self.signers if s.status == SignerStatus.PENDING]

    @property
    def next_signer(self) -> Optional[Signer]:
        """Next signer in order, or None if all have signed."""
        pending = sorted(self.pending_signers, key=lambda s: s.order)
        return pending[0] if pending else None
