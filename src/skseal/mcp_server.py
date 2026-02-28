"""SKSeal MCP Server — document signing tools for AI agents.

Exposes SKSeal's document signing workflow as MCP tools so any AI
agent (Cursor, Claude Code, Claude Desktop, Windsurf, Cline…) can
orchestrate the full PGP-backed signing lifecycle via tool calls.

Tools:
    list_templates            — List available document templates
    create_document           — Create a new document from a template
    list_documents            — List all documents with optional status filter
    sign_document             — Apply a PGP signature to a document
    verify_document           — Verify all signatures on a document
    seal_document             — Finalize a fully-signed document with tamper-evident seal
    get_audit_trail           — Get the full audit history for a document
    store_public_key          — Import a signer's public PGP key
    send_signing_request_p2p  — Send a signing request via SKComm P2P transport
    check_signing_inbox       — Poll SKComm inbox for signing requests/responses
    respond_to_signing_request — Sign a received P2P request and return the signature via SKComm
    apply_signing_responses   — Apply all pending P2P signing responses to documents

Invocation (all equivalent):
    python -m skseal.mcp_server
    bash skseal/scripts/mcp-serve.sh

Client configuration (Cursor / Claude Desktop / Claude Code CLI):
    {"mcpServers": {"skseal": {
        "command": "bash", "args": ["skseal/scripts/mcp-serve.sh"]}}}
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import pgpy
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .engine import SealEngine
from .models import AuditAction, AuditEntry, Document, DocumentStatus, Signer, SignerRole
from .models_timestamp import HashAlgorithm, TimestampConfig
from .store import DocumentStore
from .timestamp import DEFAULT_TSA_URL, load_tsr_file, timestamp_document, verify_timestamp

logger = logging.getLogger("skseal.mcp")

# Module-level singletons — no HTTP needed, same process.
_engine = SealEngine()
_store = DocumentStore()

server = Server("skseal")


# ─────────────────────────────────────────────────────────────
# Response helpers
# ─────────────────────────────────────────────────────────────


def _json(data: Any) -> list[TextContent]:
    """Wrap data as a JSON TextContent response.

    Args:
        data: Any JSON-serialisable value.

    Returns:
        Single-item list containing the JSON text.
    """
    return [TextContent(type="text", text=json.dumps(data, indent=2, default=str))]


def _error(message: str) -> list[TextContent]:
    """Return an error payload as a JSON TextContent response.

    Args:
        message: Human-readable error description.

    Returns:
        Single-item list containing {"error": message}.
    """
    return [TextContent(type="text", text=json.dumps({"error": message}))]


# ─────────────────────────────────────────────────────────────
# Tool Definitions
# ─────────────────────────────────────────────────────────────


@server.list_tools()
async def list_tools() -> list[Tool]:
    """Register all SKSeal tools with the MCP server."""
    return [
        Tool(
            name="list_templates",
            description=(
                "List all available document templates stored in SKSeal. "
                "Returns template IDs, names, and descriptions."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="create_document",
            description=(
                "Create a new signing document from an existing template. "
                "Specify the signers (name, role, PGP fingerprint) who must sign."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "template_id": {
                        "type": "string",
                        "description": "ID of the template to use.",
                    },
                    "title": {
                        "type": "string",
                        "description": "Human-readable document title.",
                    },
                    "signers": {
                        "type": "array",
                        "description": "List of signers required for this document.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string", "description": "Signer's display name."},
                                "role": {
                                    "type": "string",
                                    "description": (
                                        "Signer role: signer, cosigner, witness, "
                                        "notary, steward, trustee."
                                    ),
                                },
                                "fingerprint": {
                                    "type": "string",
                                    "description": "Signer's 40-char PGP fingerprint.",
                                },
                            },
                            "required": ["name", "fingerprint"],
                        },
                    },
                },
                "required": ["template_id", "title", "signers"],
            },
        ),
        Tool(
            name="list_documents",
            description=(
                "List documents in SKSeal, optionally filtered by status. "
                "Returns document IDs, titles, status, and signer count."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": [
                            "draft",
                            "pending",
                            "partially_signed",
                            "completed",
                            "voided",
                            "expired",
                        ],
                        "description": "Filter by lifecycle status (omit for all).",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="sign_document",
            description=(
                "Apply a PGP signature to a document on behalf of a signer. "
                "Loads the private key from a file path; the signer must have "
                "a pending signing status within the document."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "document_id": {
                        "type": "string",
                        "description": "ID of the document to sign.",
                    },
                    "signer_fingerprint": {
                        "type": "string",
                        "description": "PGP fingerprint of the signer.",
                    },
                    "private_key_path": {
                        "type": "string",
                        "description": "Absolute path to the ASCII-armored PGP private key file.",
                    },
                    "passphrase": {
                        "type": "string",
                        "description": "Passphrase to unlock the private key (use '' if unprotected).",
                    },
                },
                "required": ["document_id", "signer_fingerprint", "private_key_path", "passphrase"],
            },
        ),
        Tool(
            name="verify_document",
            description=(
                "Verify all PGP signatures on a document using cached public keys. "
                "Returns per-signer verification results (true/false)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "document_id": {
                        "type": "string",
                        "description": "ID of the document to verify.",
                    },
                },
                "required": ["document_id"],
            },
        ),
        Tool(
            name="seal_document",
            description=(
                "Finalize a fully-signed document with a tamper-evident seal. "
                "Requires a sealing PGP key. The document must be in 'completed' status. "
                "Returns the SHA-256 seal hash and final document status."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "document_id": {
                        "type": "string",
                        "description": "ID of the completed document to seal.",
                    },
                    "sealing_key_path": {
                        "type": "string",
                        "description": "Absolute path to the ASCII-armored PGP sealing private key.",
                    },
                    "passphrase": {
                        "type": "string",
                        "description": "Passphrase for the sealing key (use '' if unprotected).",
                    },
                },
                "required": ["document_id", "sealing_key_path", "passphrase"],
            },
        ),
        Tool(
            name="get_audit_trail",
            description=(
                "Retrieve the full, chronological audit history for a document. "
                "Returns all events: creation, signings, verifications, completion."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "document_id": {
                        "type": "string",
                        "description": "ID of the document whose audit trail to fetch.",
                    },
                },
                "required": ["document_id"],
            },
        ),
        Tool(
            name="store_public_key",
            description=(
                "Import a signer's ASCII-armored PGP public key into SKSeal's key cache. "
                "Required before verify_document can check that signer's signature."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "fingerprint": {
                        "type": "string",
                        "description": "40-char hex PGP fingerprint of the key.",
                    },
                    "armor": {
                        "type": "string",
                        "description": "ASCII-armored PGP public key block.",
                    },
                },
                "required": ["fingerprint", "armor"],
            },
        ),
        Tool(
            name="timestamp_document",
            description=(
                "Request an RFC 3161 timestamp for a file. Submits the file hash "
                "to a Time Stamping Authority (TSA) and saves the .tsr token. "
                "Provides non-repudiation proof that the file existed at a specific time."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the file to timestamp.",
                    },
                    "tsa_url": {
                        "type": "string",
                        "description": "TSA endpoint URL (default: FreeTSA).",
                    },
                    "hash_algorithm": {
                        "type": "string",
                        "enum": ["sha256", "sha384", "sha512"],
                        "description": "Hash algorithm (default: sha256).",
                    },
                    "save_token": {
                        "type": "boolean",
                        "description": "Save .tsr file next to document (default: true).",
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="verify_timestamp",
            description=(
                "Verify an RFC 3161 timestamp token against a file. "
                "Checks that the .tsr token covers the file's current hash."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the original file.",
                    },
                    "tsr_path": {
                        "type": "string",
                        "description": "Path to the .tsr token file (default: <file>.tsr).",
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="timestamp_info",
            description=(
                "Parse and display metadata from a .tsr timestamp token file. "
                "Returns TSA name, timestamp, serial number, policy, and hash details."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tsr_path": {
                        "type": "string",
                        "description": "Path to the .tsr token file.",
                    },
                },
                "required": ["tsr_path"],
            },
        ),
        Tool(
            name="list_hardware_tokens",
            description=(
                "List available PKCS#11 hardware tokens (YubiKey, NitroKey, HSM). "
                "Shows slot IDs, labels, manufacturers, and whether signing keys are present."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "module_path": {
                        "type": "string",
                        "description": "Path to PKCS#11 module (.so/.dylib). Auto-detected if omitted.",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="sign_with_hardware_token",
            description=(
                "Sign a document using a PKCS#11 hardware token (YubiKey, NitroKey). "
                "The private key never leaves the token. Requires PIN authentication."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "document_id": {
                        "type": "string",
                        "description": "ID of the document to sign.",
                    },
                    "signer_fingerprint": {
                        "type": "string",
                        "description": "PGP fingerprint of the signer.",
                    },
                    "pin": {
                        "type": "string",
                        "description": "Hardware token PIN.",
                    },
                    "module_path": {
                        "type": "string",
                        "description": "Path to PKCS#11 module (.so/.dylib). Auto-detected if omitted.",
                    },
                    "token_label": {
                        "type": "string",
                        "description": "Token label to match (optional).",
                    },
                    "slot_id": {
                        "type": "integer",
                        "description": "Specific slot ID (optional).",
                    },
                    "key_id": {
                        "type": "string",
                        "description": "Key ID on token in hex (optional).",
                    },
                },
                "required": ["document_id", "signer_fingerprint", "pin"],
            },
        ),
        # ── P2P signing via SKComm ──────────────────────────────────────
        Tool(
            name="send_signing_request_p2p",
            description=(
                "Send a signing request to a peer via SKComm P2P transport. "
                "Delivers the document hash and signer details directly to the signer's "
                "agent — no centralized server involved. "
                "The signer receives a SIGNING_REQUEST envelope and signs locally."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "document_id": {
                        "type": "string",
                        "description": "ID of the document that requires a signature.",
                    },
                    "signer_fingerprint": {
                        "type": "string",
                        "description": "PGP fingerprint of the intended signer (recipient).",
                    },
                    "sender_fingerprint": {
                        "type": "string",
                        "description": "PGP fingerprint of the sender/requestor (optional; uses identity default).",
                    },
                    "expire_seconds": {
                        "type": "integer",
                        "description": "Seconds until the request expires (default: 86400 / 24 h).",
                    },
                },
                "required": ["document_id", "signer_fingerprint"],
            },
        ),
        Tool(
            name="check_signing_inbox",
            description=(
                "Poll the SKComm inbox for incoming signing requests (SIGNING_REQUEST) "
                "and signing responses (SIGNING_RESPONSE). "
                "Returns both types so the caller can sign pending requests or apply "
                "received signatures to documents."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "message_type": {
                        "type": "string",
                        "enum": ["requests", "responses", "both"],
                        "description": "Which message type to poll for (default: both).",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="respond_to_signing_request",
            description=(
                "Sign a P2P signing request with the local PGP key and deliver "
                "the signature back to the requestor via SKComm. "
                "The private key never leaves this machine — only the document hash "
                "and resulting signature travel over the transport."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "request_id": {
                        "type": "string",
                        "description": "request_id from the SIGNING_REQUEST payload.",
                    },
                    "document_id": {
                        "type": "string",
                        "description": "document_id from the SIGNING_REQUEST payload.",
                    },
                    "document_hash": {
                        "type": "string",
                        "description": "SHA-256 hash from the SIGNING_REQUEST payload.",
                    },
                    "signer_id": {
                        "type": "string",
                        "description": "signer_id from the SIGNING_REQUEST payload.",
                    },
                    "sender_fingerprint": {
                        "type": "string",
                        "description": "sender_fingerprint from the SIGNING_REQUEST payload (who to reply to).",
                    },
                    "private_key_path": {
                        "type": "string",
                        "description": "Absolute path to the ASCII-armored PGP private key file.",
                    },
                    "passphrase": {
                        "type": "string",
                        "description": "Passphrase to unlock the private key (use '' if unprotected).",
                    },
                    "field_values": {
                        "type": "object",
                        "description": "Field name → value map for form fields assigned to this signer.",
                    },
                },
                "required": [
                    "request_id", "document_id", "document_hash",
                    "signer_id", "sender_fingerprint",
                    "private_key_path", "passphrase",
                ],
            },
        ),
        Tool(
            name="apply_signing_responses",
            description=(
                "Poll the SKComm inbox for SIGNING_RESPONSE envelopes and apply any "
                "received signatures to the corresponding documents. "
                "Returns a list of application results per response."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "verify": {
                        "type": "boolean",
                        "description": "Whether to verify the signature before applying (default: true).",
                    },
                },
                "required": [],
            },
        ),
    ]


# ─────────────────────────────────────────────────────────────
# Tool Dispatch
# ─────────────────────────────────────────────────────────────


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Dispatch incoming tool calls to the appropriate handler.

    Args:
        name: Tool name as registered in list_tools.
        arguments: Tool input arguments from the MCP client.

    Returns:
        List of TextContent responses.
    """
    handlers = {
        "list_templates": _handle_list_templates,
        "create_document": _handle_create_document,
        "list_documents": _handle_list_documents,
        "sign_document": _handle_sign_document,
        "verify_document": _handle_verify_document,
        "seal_document": _handle_seal_document,
        "get_audit_trail": _handle_get_audit_trail,
        "store_public_key": _handle_store_public_key,
        "timestamp_document": _handle_timestamp_document,
        "verify_timestamp": _handle_verify_timestamp,
        "timestamp_info": _handle_timestamp_info,
        "list_hardware_tokens": _handle_list_hardware_tokens,
        "sign_with_hardware_token": _handle_sign_with_hardware_token,
        "send_signing_request_p2p": _handle_send_signing_request_p2p,
        "check_signing_inbox": _handle_check_signing_inbox,
        "respond_to_signing_request": _handle_respond_to_signing_request,
        "apply_signing_responses": _handle_apply_signing_responses,
    }
    handler = handlers.get(name)
    if handler is None:
        return _error(f"Unknown tool: {name}")
    try:
        return await handler(arguments)
    except Exception as exc:
        logger.exception("Tool '%s' failed", name)
        return _error(f"{name} failed: {exc}")


# ─────────────────────────────────────────────────────────────
# Tool Handlers
# ─────────────────────────────────────────────────────────────


async def _handle_list_templates(_args: dict) -> list[TextContent]:
    """Return a summary list of all stored templates.

    Args:
        _args: Unused (no parameters required).

    Returns:
        JSON list of {template_id, name, description, created_at}.
    """
    templates = _store.list_templates()
    return _json([
        {
            "template_id": t.template_id,
            "name": t.name,
            "description": t.description,
            "created_at": t.created_at.isoformat(),
            "version": t.version,
            "folder": t.folder_name,
        }
        for t in templates
    ])


async def _handle_create_document(args: dict) -> list[TextContent]:
    """Create a new document from a template and a list of signers.

    Args:
        args: Expects template_id (str), title (str),
              signers (list of {name, role?, fingerprint}).

    Returns:
        JSON {document_id, title, status, signer_count}.
    """
    template_id: str = args.get("template_id", "")
    title: str = args.get("title", "")
    signers_raw: list[dict] = args.get("signers", [])

    if not template_id:
        return _error("template_id is required")
    if not title:
        return _error("title is required")
    if not signers_raw:
        return _error("at least one signer is required")

    try:
        template = _store.load_template(template_id)
    except FileNotFoundError:
        return _error(f"Template not found: {template_id}")

    signers: list[Signer] = []
    for idx, s in enumerate(signers_raw):
        name = s.get("name", "")
        fingerprint = s.get("fingerprint", "")
        if not name or not fingerprint:
            return _error(f"Signer {idx} missing name or fingerprint")

        role_str = s.get("role", "signer")
        try:
            role = SignerRole(role_str)
        except ValueError:
            role = SignerRole.SIGNER

        signers.append(
            Signer(
                name=name,
                fingerprint=fingerprint,
                role=role,
                order=idx,
            )
        )

    document = Document(
        title=title,
        template_id=template_id,
        signers=signers,
        status=DocumentStatus.PENDING,
        fields=template.documents[0].fields if template.documents else [],
    )

    # Record creation in the document's own audit trail.
    from datetime import datetime, timezone

    document.audit_trail.append(
        AuditEntry(
            document_id=document.document_id,
            action=AuditAction.CREATED,
            timestamp=datetime.now(timezone.utc),
            details=f"Created from template '{template.name}' with {len(signers)} signer(s).",
        )
    )

    _store.save_document(document)
    logger.info("Created document %s from template %s", document.document_id[:8], template_id[:8])

    return _json({
        "document_id": document.document_id,
        "title": document.title,
        "status": document.status.value,
        "signer_count": len(signers),
        "template": template.name,
    })


async def _handle_list_documents(args: dict) -> list[TextContent]:
    """Return a summary list of stored documents, optionally filtered by status.

    Args:
        args: Optional status (str).

    Returns:
        JSON list of document summaries.
    """
    status_str: str | None = args.get("status")
    status: DocumentStatus | None = None

    if status_str:
        try:
            status = DocumentStatus(status_str)
        except ValueError:
            return _error(
                f"Invalid status '{status_str}'. Valid values: "
                + ", ".join(s.value for s in DocumentStatus)
            )

    documents = _store.list_documents(status=status)
    return _json([
        {
            "document_id": d.document_id,
            "title": d.title,
            "status": d.status.value,
            "signers": [
                {"name": s.name, "status": s.status.value, "fingerprint": s.fingerprint[:16] + "..."}
                for s in d.signers
            ],
            "created_at": d.created_at.isoformat(),
            "completed_at": d.completed_at.isoformat() if d.completed_at else None,
        }
        for d in documents
    ])


async def _handle_sign_document(args: dict) -> list[TextContent]:
    """Load a PGP private key from disk and apply a signature to a document.

    The signer is located by fingerprint match within the document's signer list.

    Args:
        args: document_id, signer_fingerprint, private_key_path, passphrase.

    Returns:
        JSON {signed, signer_name, fingerprint, document_status, record_id}.
    """
    document_id: str = args.get("document_id", "")
    signer_fingerprint: str = args.get("signer_fingerprint", "")
    private_key_path: str = args.get("private_key_path", "")
    passphrase: str = args.get("passphrase", "")

    if not document_id:
        return _error("document_id is required")
    if not signer_fingerprint:
        return _error("signer_fingerprint is required")
    if not private_key_path:
        return _error("private_key_path is required")

    try:
        document = _store.load_document(document_id)
    except FileNotFoundError:
        return _error(f"Document not found: {document_id}")

    # Match the signer by fingerprint (allow partial prefix match for UX).
    signer_id: str | None = None
    for s in document.signers:
        if s.fingerprint.upper().startswith(signer_fingerprint.upper()):
            signer_id = s.signer_id
            break

    if signer_id is None:
        return _error(
            f"No signer with fingerprint '{signer_fingerprint}' found in document."
        )

    key_path = Path(private_key_path)
    if not key_path.exists():
        return _error(f"Private key file not found: {private_key_path}")

    private_key_armor: str = key_path.read_text(encoding="utf-8")

    # Validate key is readable before passing to engine.
    try:
        pgpy.PGPKey.from_blob(private_key_armor)
    except Exception as exc:
        return _error(f"Failed to parse private key: {exc}")

    document = _engine.sign_document(
        document=document,
        signer_id=signer_id,
        private_key_armor=private_key_armor,
        passphrase=passphrase,
    )

    _store.save_document(document)

    # Return the most recently appended signature record.
    last_record = document.signatures[-1] if document.signatures else None

    return _json({
        "signed": True,
        "signer_id": signer_id,
        "fingerprint": last_record.fingerprint if last_record else signer_fingerprint,
        "record_id": last_record.record_id if last_record else None,
        "signed_at": last_record.signed_at.isoformat() if last_record else None,
        "document_status": document.status.value,
    })


async def _handle_verify_document(args: dict) -> list[TextContent]:
    """Verify all signatures on a document using cached public keys.

    Args:
        args: document_id (str).

    Returns:
        JSON {document_id, results: {signer_id: bool}, all_valid}.
    """
    document_id: str = args.get("document_id", "")
    if not document_id:
        return _error("document_id is required")

    try:
        document = _store.load_document(document_id)
    except FileNotFoundError:
        return _error(f"Document not found: {document_id}")

    # Build the public key map from the key cache.
    public_keys: dict[str, str] = {}
    for record in document.signatures:
        key_armor = _store.get_public_key(record.fingerprint)
        if key_armor:
            public_keys[record.fingerprint] = key_armor
        else:
            logger.warning(
                "No cached public key for fingerprint %s — verification will fail for this signer",
                record.fingerprint[:16],
            )

    results = _engine.verify_document(document, public_keys=public_keys)

    return _json({
        "document_id": document_id,
        "document_status": document.status.value,
        "results": results,
        "all_valid": all(results.values()) if results else False,
        "missing_keys": [
            fp[:16] + "..."
            for rec in document.signatures
            if rec.fingerprint not in public_keys
            for fp in [rec.fingerprint]
        ],
    })


async def _handle_seal_document(args: dict) -> list[TextContent]:
    """Create a tamper-evident PGP seal over a completed document.

    Args:
        args: document_id, sealing_key_path, passphrase.

    Returns:
        JSON {sealed, seal_hash, document_status}.
    """
    document_id: str = args.get("document_id", "")
    sealing_key_path: str = args.get("sealing_key_path", "")
    passphrase: str = args.get("passphrase", "")

    if not document_id:
        return _error("document_id is required")
    if not sealing_key_path:
        return _error("sealing_key_path is required")

    try:
        document = _store.load_document(document_id)
    except FileNotFoundError:
        return _error(f"Document not found: {document_id}")

    if document.status != DocumentStatus.COMPLETED:
        return _error(
            f"Document is not completed (current status: {document.status.value}). "
            "All signers must sign before sealing."
        )

    key_path = Path(sealing_key_path)
    if not key_path.exists():
        return _error(f"Sealing key file not found: {sealing_key_path}")

    sealing_key_armor: str = key_path.read_text(encoding="utf-8")

    seal_armor = _engine.seal_document(
        document=document,
        sealing_key_armor=sealing_key_armor,
        passphrase=passphrase,
    )

    # Store the seal armor in document metadata and persist.
    seal_hash = _engine.hash_bytes(seal_armor.encode("utf-8"))
    document.metadata["seal_hash"] = seal_hash
    document.metadata["seal_armor"] = seal_armor
    _store.save_document(document)

    return _json({
        "sealed": True,
        "document_id": document_id,
        "seal_hash": seal_hash,
        "document_status": document.status.value,
    })


async def _handle_get_audit_trail(args: dict) -> list[TextContent]:
    """Return the full audit trail for a document.

    Args:
        args: document_id (str).

    Returns:
        JSON list of audit entries sorted chronologically.
    """
    document_id: str = args.get("document_id", "")
    if not document_id:
        return _error("document_id is required")

    # Confirm the document exists before reading audit log.
    try:
        _store.load_document(document_id)
    except FileNotFoundError:
        return _error(f"Document not found: {document_id}")

    entries = _store.get_audit_trail(document_id)

    # Fallback: also read from the document's embedded audit trail.
    if not entries:
        try:
            doc = _store.load_document(document_id)
            entries = sorted(doc.audit_trail, key=lambda e: e.timestamp)
        except Exception:
            entries = []

    return _json([
        {
            "entry_id": e.entry_id,
            "action": e.action.value,
            "actor_name": e.actor_name,
            "actor_fingerprint": (e.actor_fingerprint[:16] + "...") if e.actor_fingerprint else None,
            "timestamp": e.timestamp.isoformat(),
            "details": e.details,
            "ip_address": e.ip_address,
        }
        for e in entries
    ])


async def _handle_store_public_key(args: dict) -> list[TextContent]:
    """Import an ASCII-armored PGP public key into SKSeal's key cache.

    Args:
        args: fingerprint (str), armor (str).

    Returns:
        JSON {stored, fingerprint, path}.
    """
    fingerprint: str = args.get("fingerprint", "")
    armor: str = args.get("armor", "")

    if not fingerprint:
        return _error("fingerprint is required")
    if not armor:
        return _error("armor is required")

    # Validate the key is parseable before caching it.
    try:
        key, _ = pgpy.PGPKey.from_blob(armor)
        actual_fp = str(key.fingerprint).replace(" ", "")
    except Exception as exc:
        return _error(f"Failed to parse public key: {exc}")

    path = _store.store_public_key(fingerprint, armor)

    return _json({
        "stored": True,
        "fingerprint": fingerprint,
        "actual_fingerprint": actual_fp,
        "path": str(path),
    })


# ─────────────────────────────────────────────────────────────
# Timestamp Tool Handlers
# ─────────────────────────────────────────────────────────────


async def _handle_timestamp_document(args: dict) -> list[TextContent]:
    """Request an RFC 3161 timestamp for a file.

    Args:
        args: file_path (str), optional tsa_url, hash_algorithm, save_token.

    Returns:
        JSON with timestamp result details.
    """
    file_path: str = args.get("file_path", "")
    if not file_path:
        return _error("file_path is required")

    path = Path(file_path)
    if not path.exists():
        return _error(f"File not found: {file_path}")

    tsa_url: str = args.get("tsa_url", DEFAULT_TSA_URL)
    algo_str: str = args.get("hash_algorithm", "sha256")
    save_token: bool = args.get("save_token", True)

    try:
        algo = HashAlgorithm(algo_str)
    except ValueError:
        return _error(f"Invalid hash algorithm: {algo_str}")

    config = TimestampConfig(tsa_url=tsa_url, hash_algorithm=algo)

    try:
        result = timestamp_document(file_path, config=config, save_token=save_token)
    except Exception as exc:
        return _error(f"Timestamp request failed: {exc}")

    return _json({
        "file_path": result.file_path,
        "file_hash": result.file_hash,
        "status": result.verification_status.value,
        "tsa_url": result.tsa_url,
        "tsr_path": result.tsr_path,
        "timestamp": (
            result.response.timestamp.isoformat()
            if result.response and result.response.timestamp
            else None
        ),
        "serial_number": (
            result.response.serial_number if result.response else None
        ),
        "error": result.error,
    })


async def _handle_verify_timestamp(args: dict) -> list[TextContent]:
    """Verify an RFC 3161 timestamp token against a file.

    Args:
        args: file_path (str), optional tsr_path (str).

    Returns:
        JSON with verification result.
    """
    file_path: str = args.get("file_path", "")
    if not file_path:
        return _error("file_path is required")

    path = Path(file_path)
    if not path.exists():
        return _error(f"File not found: {file_path}")

    tsr_path: str = args.get("tsr_path", "")
    if not tsr_path:
        tsr_path = file_path + ".tsr"

    if not Path(tsr_path).exists():
        return _error(f"TSR file not found: {tsr_path}")

    file_bytes = path.read_bytes()
    response = load_tsr_file(tsr_path)
    is_valid = verify_timestamp(response, file_bytes)

    return _json({
        "file_path": file_path,
        "tsr_path": tsr_path,
        "valid": is_valid,
        "tsa_url": response.tsa_url,
        "timestamp": (
            response.timestamp.isoformat() if response.timestamp else None
        ),
        "serial_number": response.serial_number,
    })


async def _handle_timestamp_info(args: dict) -> list[TextContent]:
    """Parse and display metadata from a .tsr token file.

    Args:
        args: tsr_path (str).

    Returns:
        JSON with token metadata.
    """
    tsr_path: str = args.get("tsr_path", "")
    if not tsr_path:
        return _error("tsr_path is required")

    if not Path(tsr_path).exists():
        return _error(f"TSR file not found: {tsr_path}")

    response = load_tsr_file(tsr_path)

    return _json({
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
        "tsa_name": response.tsa_name,
        "policy_id": response.policy_id,
        "nonce": response.nonce,
        "accuracy_seconds": response.accuracy_seconds,
    })


# ─────────────────────────────────────────────────────────────
# Hardware Token Tool Handlers
# ─────────────────────────────────────────────────────────────


async def _handle_list_hardware_tokens(args: dict) -> list[TextContent]:
    """List available PKCS#11 hardware tokens.

    Args:
        args: Optional module_path.

    Returns:
        JSON list of token info.
    """
    from .pkcs11 import list_tokens

    module_path: str | None = args.get("module_path")

    try:
        tokens = list_tokens(module_path)
    except RuntimeError as exc:
        return _error(str(exc))

    return _json([
        {
            "slot_id": t.slot_id,
            "label": t.label,
            "manufacturer": t.manufacturer,
            "model": t.model,
            "serial": t.serial,
            "has_private_key": t.has_private_key,
            "key_id": t.key_id,
            "key_label": t.key_label,
        }
        for t in tokens
    ])


async def _handle_sign_with_hardware_token(args: dict) -> list[TextContent]:
    """Sign a document using a PKCS#11 hardware token.

    Args:
        args: document_id, signer_fingerprint, pin, optional module/token/slot/key.

    Returns:
        JSON with signing result.
    """
    from .pkcs11 import PKCS11Config

    document_id: str = args.get("document_id", "")
    signer_fingerprint: str = args.get("signer_fingerprint", "")
    pin: str = args.get("pin", "")

    if not document_id:
        return _error("document_id is required")
    if not signer_fingerprint:
        return _error("signer_fingerprint is required")
    if not pin:
        return _error("pin is required")

    try:
        document = _store.load_document(document_id)
    except FileNotFoundError:
        return _error(f"Document not found: {document_id}")

    # Match signer by fingerprint prefix
    signer_id: str | None = None
    for s in document.signers:
        if s.fingerprint.upper().startswith(signer_fingerprint.upper()):
            signer_id = s.signer_id
            break

    if signer_id is None:
        return _error(
            f"No signer with fingerprint '{signer_fingerprint}' found in document."
        )

    config = PKCS11Config(
        module_path=args.get("module_path", ""),
        token_label=args.get("token_label"),
        slot_id=args.get("slot_id"),
        pin=pin,
        key_id=args.get("key_id"),
    )

    try:
        document = _engine.sign_document_pkcs11(
            document=document,
            signer_id=signer_id,
            config=config,
        )
    except (ValueError, RuntimeError) as exc:
        return _error(str(exc))

    _store.save_document(document)

    last_record = document.signatures[-1] if document.signatures else None

    return _json({
        "signed": True,
        "method": "pkcs11",
        "signer_id": signer_id,
        "fingerprint": last_record.fingerprint if last_record else signer_fingerprint,
        "record_id": last_record.record_id if last_record else None,
        "signed_at": last_record.signed_at.isoformat() if last_record else None,
        "document_status": document.status.value,
    })


# ─────────────────────────────────────────────────────────────
# P2P Signing Tool Handlers (SKComm transport)
# ─────────────────────────────────────────────────────────────


def _get_skcomm():
    """Initialise an SKComm instance from the default config.

    Returns:
        SKComm instance, or None if skcomm is not installed/configured.
    """
    try:
        from skcomm import SKComm
        return SKComm.from_config()
    except Exception as exc:
        logger.warning("SKComm unavailable: %s", exc)
        return None


async def _handle_send_signing_request_p2p(args: dict) -> list[TextContent]:
    """Send a SIGNING_REQUEST to a peer via SKComm P2P transport.

    Args:
        args: document_id, signer_fingerprint, optional sender_fingerprint,
              optional expire_seconds.

    Returns:
        JSON {request_id, delivered, transport, error}.
    """
    from .skcomm_transport import SealSKCommTransport

    document_id: str = args.get("document_id", "")
    signer_fingerprint: str = args.get("signer_fingerprint", "")

    if not document_id:
        return _error("document_id is required")
    if not signer_fingerprint:
        return _error("signer_fingerprint is required")

    skcomm = _get_skcomm()
    if skcomm is None:
        return _error(
            "SKComm is not available. Install skcomm and configure ~/.skcomm/config.yml"
        )

    transport = SealSKCommTransport(
        store=_store,
        identity_fingerprint=args.get("sender_fingerprint", ""),
    )

    try:
        result = transport.send_signing_request(
            skcomm=skcomm,
            document_id=document_id,
            signer_fingerprint=signer_fingerprint,
            sender_fingerprint=args.get("sender_fingerprint") or None,
            expire_seconds=int(args.get("expire_seconds", 86400)),
        )
    except FileNotFoundError:
        return _error(f"Document not found: {document_id}")
    except ValueError as exc:
        return _error(str(exc))

    return _json(result)


async def _handle_check_signing_inbox(args: dict) -> list[TextContent]:
    """Poll SKComm inbox for SIGNING_REQUEST and/or SIGNING_RESPONSE envelopes.

    Args:
        args: Optional message_type ("requests" | "responses" | "both").

    Returns:
        JSON {requests: [...], responses: [...]}.
    """
    from .skcomm_transport import SealSKCommTransport

    message_type: str = args.get("message_type", "both")

    skcomm = _get_skcomm()
    if skcomm is None:
        return _error(
            "SKComm is not available. Install skcomm and configure ~/.skcomm/config.yml"
        )

    transport = SealSKCommTransport(store=_store)

    # We need to receive envelopes once and split by type to avoid double-consuming.
    # Use lower-level receive and filter manually.
    requests_list = []
    responses_list = []

    try:
        from skcomm.models import MessageType

        envelopes = skcomm.receive()
        import json as _json_mod

        for env in envelopes:
            try:
                ct = env.payload.content_type
                payload = _json_mod.loads(env.payload.content)
                payload["_envelope_id"] = env.envelope_id
                payload["_sender"] = env.sender

                if ct == MessageType.SIGNING_REQUEST:
                    requests_list.append(payload)
                elif ct == MessageType.SIGNING_RESPONSE:
                    responses_list.append(payload)
            except Exception:
                continue
    except Exception as exc:
        return _error(f"Failed to poll SKComm inbox: {exc}")

    result: dict = {}
    if message_type in ("requests", "both"):
        result["requests"] = requests_list
    if message_type in ("responses", "both"):
        result["responses"] = responses_list

    result["total"] = len(requests_list) + len(responses_list)
    return _json(result)


async def _handle_respond_to_signing_request(args: dict) -> list[TextContent]:
    """Sign a P2P signing request and deliver the signature via SKComm.

    The private key is loaded from disk, used to sign the document hash,
    and the key material never leaves this machine — only the hash and
    signature travel over SKComm.

    Args:
        args: request_id, document_id, document_hash, signer_id,
              sender_fingerprint, private_key_path, passphrase,
              optional field_values.

    Returns:
        JSON {request_id, signed, signer_fingerprint, delivered, transport, error}.
    """
    from .skcomm_transport import SealSKCommTransport

    required = ["request_id", "document_id", "document_hash",
                "signer_id", "sender_fingerprint", "private_key_path", "passphrase"]
    for field in required:
        if not args.get(field) and field != "passphrase":
            return _error(f"{field} is required")

    private_key_path = Path(args["private_key_path"])
    if not private_key_path.exists():
        return _error(f"Private key file not found: {args['private_key_path']}")

    private_key_armor = private_key_path.read_text(encoding="utf-8")
    try:
        pgpy.PGPKey.from_blob(private_key_armor)
    except Exception as exc:
        return _error(f"Failed to parse private key: {exc}")

    skcomm = _get_skcomm()
    if skcomm is None:
        return _error(
            "SKComm is not available. Install skcomm and configure ~/.skcomm/config.yml"
        )

    # Reconstruct the request_payload dict from individual args
    request_payload = {
        "request_id": args["request_id"],
        "document_id": args["document_id"],
        "document_hash": args["document_hash"],
        "signer_id": args["signer_id"],
        "sender_fingerprint": args["sender_fingerprint"],
    }

    transport = SealSKCommTransport(store=_store)
    result = transport.respond_to_signing_request(
        skcomm=skcomm,
        request_payload=request_payload,
        private_key_armor=private_key_armor,
        passphrase=args.get("passphrase", ""),
        field_values=args.get("field_values"),
    )
    return _json(result)


async def _handle_apply_signing_responses(args: dict) -> list[TextContent]:
    """Poll for SIGNING_RESPONSE envelopes and apply them to documents.

    Args:
        args: Optional verify (bool, default True).

    Returns:
        JSON list of {request_id, document_id, applied, document_status, error}.
    """
    from .skcomm_transport import SealSKCommTransport

    verify: bool = args.get("verify", True)

    skcomm = _get_skcomm()
    if skcomm is None:
        return _error(
            "SKComm is not available. Install skcomm and configure ~/.skcomm/config.yml"
        )

    transport = SealSKCommTransport(store=_store)
    results = transport.poll_and_apply_responses(skcomm, verify=verify)
    return _json(results)


# ─────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────


def main() -> None:
    """Run the SKSeal MCP server on stdio transport."""
    logging.basicConfig(level=logging.WARNING, format="%(name)s: %(message)s")
    asyncio.run(_run_server())


async def _run_server() -> None:
    """Async entry point for the stdio MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


if __name__ == "__main__":
    main()
