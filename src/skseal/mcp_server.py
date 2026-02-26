"""SKSeal MCP Server — document signing tools for AI agents.

Exposes SKSeal's document signing workflow as MCP tools so any AI
agent (Cursor, Claude Code, Claude Desktop, Windsurf, Cline…) can
orchestrate the full PGP-backed signing lifecycle via tool calls.

Tools:
    list_templates      — List available document templates
    create_document     — Create a new document from a template
    list_documents      — List all documents with optional status filter
    sign_document       — Apply a PGP signature to a document
    verify_document     — Verify all signatures on a document
    seal_document       — Finalize a fully-signed document with tamper-evident seal
    get_audit_trail     — Get the full audit history for a document
    store_public_key    — Import a signer's public PGP key

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
from .store import DocumentStore

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
