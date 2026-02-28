"""SKSeal REST API — FastAPI server for sovereign document signing.

Endpoints mirror DocuSeal's REST API conventions where possible
for SDK/integration compatibility, but add PGP-specific operations
(sign with key, verify signature, seal document).
"""

import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

from .engine import SealEngine
from .models import (
    AuditAction,
    AuditEntry,
    Document,
    DocumentField,
    DocumentStatus,
    SignatureRecord,
    Signer,
    SignerStatus,
    Template,
)
from .models_timestamp import HashAlgorithm, TimestampConfig, TimestampStatus
from .store import DocumentStore
from .timestamp import (
    DEFAULT_TSA_URL,
    load_tsr_file,
    timestamp_document,
    verify_timestamp,
)

logger = logging.getLogger("skseal.api")

app = FastAPI(
    title="SKSeal",
    description="Sovereign Document Signing — PGP-backed, legally binding, no middleman.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_store = DocumentStore()
_engine = SealEngine()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class CreateDocumentRequest(BaseModel):
    """Request body for creating a new signing document."""

    title: str
    description: str = ""
    template_id: Optional[str] = None
    signers: list[Signer] = []
    fields: list[DocumentField] = []
    created_by: Optional[str] = None
    metadata: dict[str, str] = {}


class SignRequest(BaseModel):
    """Request body for signing a document."""

    signer_id: str
    private_key_armor: str
    passphrase: str
    field_values: dict[str, str] = {}


class VerifyRequest(BaseModel):
    """Request body for verifying a document's signatures."""

    public_keys: dict[str, str] = {}


class ClientSignRequest(BaseModel):
    """Request body for submitting a client-side signature.

    The browser signs locally with OpenPGP.js and sends only the
    signature — the private key never leaves the client.
    """

    signer_id: str
    signature_armor: str
    document_hash: str
    fingerprint: str
    field_values: dict[str, str] = {}


class SealRequest(BaseModel):
    """Request body for sealing a completed document."""

    sealing_key_armor: str
    passphrase: str


class TimestampRequest(BaseModel):
    """Request body for timestamping a document."""

    tsa_url: Optional[str] = None
    hash_algorithm: str = "sha256"


class VerifyTimestampRequest(BaseModel):
    """Request body for verifying a timestamp."""

    tsr_path: Optional[str] = None


class VerifyResult(BaseModel):
    """Verification result per signer."""

    signer_id: str
    signer_name: str
    fingerprint: str
    valid: bool


# ---------------------------------------------------------------------------
# Template endpoints
# ---------------------------------------------------------------------------

@app.post("/api/templates", response_model=Template, status_code=201)
async def create_template(template: Template) -> Template:
    """Create a new document template."""
    _store.save_template(template)
    return template


@app.get("/api/templates", response_model=list[Template])
async def list_templates() -> list[Template]:
    """List all templates."""
    return _store.list_templates()


@app.get("/api/templates/{template_id}", response_model=Template)
async def get_template(template_id: str) -> Template:
    """Get a template by ID."""
    try:
        return _store.load_template(template_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")


@app.delete("/api/templates/{template_id}", status_code=204)
async def delete_template(template_id: str) -> None:
    """Delete a template."""
    if not _store.delete_template(template_id):
        raise HTTPException(status_code=404, detail="Template not found")


# ---------------------------------------------------------------------------
# Document endpoints
# ---------------------------------------------------------------------------

@app.post("/api/documents", response_model=Document, status_code=201)
async def create_document(req: CreateDocumentRequest) -> Document:
    """Create a new signing document.

    Optionally creates from a template. The document starts in DRAFT
    status and moves to PENDING when sent to signers.
    """
    doc = Document(
        title=req.title,
        description=req.description,
        template_id=req.template_id,
        signers=req.signers,
        fields=req.fields,
        created_by=req.created_by,
        metadata=req.metadata,
    )

    if req.template_id:
        try:
            template = _store.load_template(req.template_id)
            for td in template.documents:
                doc.fields.extend(td.fields)
        except FileNotFoundError:
            raise HTTPException(
                status_code=404, detail=f"Template {req.template_id} not found"
            )

    doc.audit_trail.append(
        AuditEntry(
            document_id=doc.document_id,
            action=AuditAction.CREATED,
            actor_fingerprint=req.created_by,
            details=f"Document created: {req.title}",
        )
    )
    _store.save_document(doc)

    for entry in doc.audit_trail:
        _store.append_audit(entry)

    return doc


@app.post("/api/documents/{document_id}/upload", response_model=Document)
async def upload_pdf(document_id: str, file: UploadFile = File(...)) -> Document:
    """Upload a PDF for an existing document."""
    try:
        doc = _store.load_document(document_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")

    pdf_data = await file.read()
    doc.pdf_hash = _engine.hash_bytes(pdf_data)
    _store.save_document(doc, pdf_data=pdf_data)
    return doc


@app.get("/api/documents", response_model=list[Document])
async def list_documents(
    status: Optional[str] = Query(None, description="Filter by status"),
) -> list[Document]:
    """List documents, optionally filtered by status."""
    status_filter = DocumentStatus(status) if status else None
    return _store.list_documents(status=status_filter)


@app.get("/api/documents/{document_id}", response_model=Document)
async def get_document(document_id: str) -> Document:
    """Get a document by ID."""
    try:
        return _store.load_document(document_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")


@app.get("/api/documents/{document_id}/pdf")
async def download_pdf(document_id: str) -> Response:
    """Download the source PDF for a document."""
    pdf_data = _store.get_document_pdf(document_id)
    if pdf_data is None:
        raise HTTPException(status_code=404, detail="No PDF attached")
    return Response(content=pdf_data, media_type="application/pdf")


@app.get("/api/documents/{document_id}/audit", response_model=list[AuditEntry])
async def get_audit_trail(document_id: str) -> list[AuditEntry]:
    """Get the audit trail for a document."""
    return _store.get_audit_trail(document_id)


@app.delete("/api/documents/{document_id}", status_code=204)
async def delete_document(document_id: str) -> None:
    """Delete a document and all associated files."""
    if not _store.delete_document(document_id):
        raise HTTPException(status_code=404, detail="Document not found")


# ---------------------------------------------------------------------------
# Signing endpoints
# ---------------------------------------------------------------------------

@app.post("/api/documents/{document_id}/sign", response_model=Document)
async def sign_document(document_id: str, req: SignRequest) -> Document:
    """Sign a document with a PGP key.

    The private key is used transiently for signing and is never stored.
    In production, client-side signing with OpenPGP.js is preferred —
    this endpoint exists for server-side automation and agent workflows.
    """
    try:
        doc = _store.load_document(document_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")

    pdf_data = _store.get_document_pdf(document_id)

    try:
        doc = _engine.sign_document(
            document=doc,
            signer_id=req.signer_id,
            private_key_armor=req.private_key_armor,
            passphrase=req.passphrase,
            pdf_data=pdf_data,
            field_values=req.field_values,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    _store.save_document(doc)

    for entry in doc.audit_trail:
        _store.append_audit(entry)

    return doc


@app.post("/api/documents/{document_id}/sign-client", response_model=Document)
async def sign_document_client(
    document_id: str, req: ClientSignRequest
) -> Document:
    """Accept a pre-computed client-side PGP signature.

    This is the preferred signing endpoint for browser-based workflows.
    The client signs the document hash locally using OpenPGP.js and submits
    only the signature. Private keys NEVER leave the browser.

    The server:
    1. Validates the signature against the cached public key
    2. Verifies the document hash matches the stored PDF
    3. Records the signature and updates document status
    """
    try:
        doc = _store.load_document(document_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")

    # Validate signer exists
    signer = None
    for s in doc.signers:
        if s.signer_id == req.signer_id:
            signer = s
            break
    if signer is None:
        raise HTTPException(status_code=400, detail="Signer not found")
    if signer.status == SignerStatus.SIGNED:
        raise HTTPException(status_code=400, detail="Signer has already signed")

    # Verify document hash matches stored PDF
    pdf_data = _store.get_document_pdf(document_id)
    if pdf_data is not None:
        stored_hash = _engine.hash_bytes(pdf_data)
        if stored_hash != req.document_hash:
            raise HTTPException(
                status_code=400,
                detail="Document hash mismatch — PDF may have been modified",
            )

    # Verify the signature using the cached public key
    public_key = _store.get_public_key(req.fingerprint)
    if public_key is None:
        raise HTTPException(
            status_code=400,
            detail=f"No cached public key for {req.fingerprint[:16]}...",
        )

    record = SignatureRecord(
        document_id=document_id,
        signer_id=req.signer_id,
        fingerprint=req.fingerprint,
        document_hash=req.document_hash,
        signature_armor=req.signature_armor,
        field_values=req.field_values,
    )

    # Verify signature is cryptographically valid
    is_valid = _engine.verify_signature(record, public_key, pdf_data=pdf_data)
    if not is_valid:
        raise HTTPException(
            status_code=400, detail="Signature verification failed"
        )

    # Record the signature
    doc.signatures.append(record)
    now = record.signed_at
    signer.status = SignerStatus.SIGNED
    signer.signed_at = now
    signer.fingerprint = req.fingerprint

    doc.audit_trail.append(
        AuditEntry(
            document_id=document_id,
            action=AuditAction.SIGNED,
            actor_fingerprint=req.fingerprint,
            actor_name=signer.name,
            timestamp=now,
            details=f"Client-side signed with key {req.fingerprint[:16]}...",
        )
    )

    if doc.is_complete:
        doc.status = DocumentStatus.COMPLETED
        doc.completed_at = now
        doc.audit_trail.append(
            AuditEntry(
                document_id=document_id,
                action=AuditAction.COMPLETED,
                timestamp=now,
                details="All signers have signed.",
            )
        )
    else:
        doc.status = DocumentStatus.PARTIALLY_SIGNED

    _store.save_document(doc)
    for entry in doc.audit_trail:
        _store.append_audit(entry)

    return doc


@app.post("/api/documents/{document_id}/verify", response_model=list[VerifyResult])
async def verify_document(document_id: str, req: VerifyRequest) -> list[VerifyResult]:
    """Verify all signatures on a document.

    Provide public keys in the request body, or the engine will look
    them up from the local key cache.
    """
    try:
        doc = _store.load_document(document_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")

    public_keys = dict(req.public_keys)
    for record in doc.signatures:
        if record.fingerprint not in public_keys:
            cached = _store.get_public_key(record.fingerprint)
            if cached:
                public_keys[record.fingerprint] = cached

    pdf_data = _store.get_document_pdf(document_id)
    results = _engine.verify_document(doc, public_keys, pdf_data=pdf_data)

    signer_map = {s.signer_id: s for s in doc.signers}
    return [
        VerifyResult(
            signer_id=sid,
            signer_name=signer_map.get(sid, Signer(name="Unknown", fingerprint="")).name,
            fingerprint=next(
                (r.fingerprint for r in doc.signatures if r.signer_id == sid), ""
            ),
            valid=valid,
        )
        for sid, valid in results.items()
    ]


@app.post("/api/documents/{document_id}/seal")
async def seal_document(document_id: str, req: SealRequest) -> dict:
    """Seal a completed document with a tamper-evident envelope.

    Creates a PGP signature over the entire document package
    (all signatures + audit trail).
    """
    try:
        doc = _store.load_document(document_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")

    try:
        seal = _engine.seal_document(doc, req.sealing_key_armor, req.passphrase)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {"document_id": document_id, "seal": seal, "status": "sealed"}


# ---------------------------------------------------------------------------
# Key management endpoints
# ---------------------------------------------------------------------------

@app.post("/api/keys", status_code=201)
async def store_public_key(fingerprint: str, armor: str) -> dict:
    """Cache a public key for future verification."""
    _store.store_public_key(fingerprint, armor)
    return {"fingerprint": fingerprint, "stored": True}


@app.get("/api/keys")
async def list_keys() -> list[str]:
    """List all cached public key fingerprints."""
    return _store.list_public_keys()


# ---------------------------------------------------------------------------
# Timestamp endpoints (RFC 3161)
# ---------------------------------------------------------------------------

@app.post("/api/documents/{document_id}/timestamp")
async def timestamp_doc(document_id: str, req: TimestampRequest) -> dict:
    """Request an RFC 3161 timestamp for a document.

    Submits the document's PDF hash to a Time Stamping Authority (TSA)
    and saves the resulting .tsr token alongside the document.
    """
    try:
        doc = _store.load_document(document_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")

    pdf_data = _store.get_document_pdf(document_id)
    if pdf_data is None:
        raise HTTPException(status_code=400, detail="No PDF attached to document")

    # Write PDF to a temp file for timestamp_document()
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp.write(pdf_data)
        tmp_path = tmp.name

    try:
        algo = HashAlgorithm(req.hash_algorithm)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid hash algorithm: {req.hash_algorithm}",
        )

    config = TimestampConfig(
        tsa_url=req.tsa_url or DEFAULT_TSA_URL,
        hash_algorithm=algo,
    )

    try:
        result = timestamp_document(tmp_path, config=config, save_token=True)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Timestamp request failed: {exc}")
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    doc.audit_trail.append(
        AuditEntry(
            document_id=document_id,
            action=AuditAction.SIGNED,
            details=f"RFC 3161 timestamp from {result.tsa_url}: {result.verification_status.value}",
        )
    )
    doc.metadata["timestamp_status"] = result.verification_status.value
    doc.metadata["timestamp_tsa"] = result.tsa_url
    if result.response and result.response.timestamp:
        doc.metadata["timestamp_time"] = result.response.timestamp.isoformat()
    if result.tsr_path:
        doc.metadata["timestamp_tsr_path"] = result.tsr_path

    _store.save_document(doc)
    for entry in doc.audit_trail:
        _store.append_audit(entry)

    return {
        "document_id": document_id,
        "status": result.verification_status.value,
        "tsa_url": result.tsa_url,
        "file_hash": result.file_hash,
        "tsr_path": result.tsr_path,
        "timestamp": (
            result.response.timestamp.isoformat()
            if result.response and result.response.timestamp
            else None
        ),
        "error": result.error,
    }


@app.post("/api/documents/{document_id}/timestamp/verify")
async def verify_doc_timestamp(
    document_id: str, req: VerifyTimestampRequest
) -> dict:
    """Verify an RFC 3161 timestamp token against a document's PDF."""
    try:
        doc = _store.load_document(document_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")

    pdf_data = _store.get_document_pdf(document_id)
    if pdf_data is None:
        raise HTTPException(status_code=400, detail="No PDF attached to document")

    tsr_path = req.tsr_path or doc.metadata.get("timestamp_tsr_path")
    if not tsr_path:
        raise HTTPException(
            status_code=400,
            detail="No .tsr path provided and no timestamp on record",
        )

    if not Path(tsr_path).exists():
        raise HTTPException(status_code=404, detail=f"TSR file not found: {tsr_path}")

    tsa_url = doc.metadata.get("timestamp_tsa", DEFAULT_TSA_URL)
    response = load_tsr_file(tsr_path, tsa_url=tsa_url)
    is_valid = verify_timestamp(response, pdf_data)

    return {
        "document_id": document_id,
        "valid": is_valid,
        "status": "valid" if is_valid else "invalid",
        "tsa_url": tsa_url,
        "timestamp": (
            response.timestamp.isoformat() if response.timestamp else None
        ),
        "serial_number": response.serial_number,
    }


@app.get("/api/timestamp/info")
async def timestamp_info(tsr_path: str = Query(..., description="Path to .tsr file")) -> dict:
    """Parse and display metadata from a .tsr token file."""
    if not Path(tsr_path).exists():
        raise HTTPException(status_code=404, detail=f"TSR file not found: {tsr_path}")

    response = load_tsr_file(tsr_path)
    return {
        "tsr_path": tsr_path,
        "status": response.status,
        "is_granted": response.is_granted,
        "tsa_url": response.tsa_url,
        "timestamp": (
            response.timestamp.isoformat() if response.timestamp else None
        ),
        "serial_number": response.serial_number,
        "hash_algorithm": response.hash_algorithm.value,
        "message_imprint": response.message_imprint,
        "policy_id": response.policy_id,
        "nonce": response.nonce,
        "accuracy_seconds": response.accuracy_seconds,
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health() -> dict:
    """Health check."""
    return {
        "status": "ok",
        "service": "skseal",
        "version": "0.1.0",
    }
