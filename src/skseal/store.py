"""Filesystem-backed document and template store for SKSeal.

Everything lives on disk as JSON + PDF files under ``~/.skseal/``.
Syncthing-friendly, git-friendly, no database required. The store
structure mirrors DocuSeal's logical organization while keeping
the sovereign filesystem-first philosophy.

Directory layout::

    ~/.skseal/
    ├── templates/          # Reusable templates (JSON)
    ├── documents/          # Signing documents (JSON + PDF)
    │   ├── <doc-id>/
    │   │   ├── document.json
    │   │   ├── source.pdf
    │   │   └── sealed.pdf  (after completion)
    ├── audit/              # Append-only audit logs (JSONL)
    └── keys/               # Cached public keys for verification
"""

import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import (
    AuditAction,
    AuditEntry,
    Document,
    DocumentStatus,
    Template,
)

logger = logging.getLogger("skseal.store")

DEFAULT_SKSEAL_DIR = Path.home() / ".skseal"


class DocumentStore:
    """Filesystem-backed CRUD for documents, templates, and audit logs.

    Args:
        base_dir: Root directory for all skseal data.
    """

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.base = base_dir or DEFAULT_SKSEAL_DIR
        self._templates_dir = self.base / "templates"
        self._documents_dir = self.base / "documents"
        self._audit_dir = self.base / "audit"
        self._keys_dir = self.base / "keys"

        for d in (
            self._templates_dir,
            self._documents_dir,
            self._audit_dir,
            self._keys_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Templates
    # ------------------------------------------------------------------

    def save_template(self, template: Template) -> Path:
        """Save a template to disk.

        Args:
            template: Template to persist.

        Returns:
            Path to the saved JSON file.
        """
        path = self._templates_dir / f"{template.template_id}.json"
        path.write_text(
            template.model_dump_json(indent=2, by_alias=True),
            encoding="utf-8",
        )
        logger.info("Saved template %s (%s)", template.name, template.template_id[:8])
        return path

    def load_template(self, template_id: str) -> Template:
        """Load a template by ID.

        Args:
            template_id: Unique template identifier.

        Returns:
            The Template.

        Raises:
            FileNotFoundError: If the template doesn't exist.
        """
        path = self._templates_dir / f"{template_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"Template not found: {template_id}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return Template.model_validate(data)

    def list_templates(self) -> list[Template]:
        """List all templates, sorted by creation date (newest first)."""
        templates = []
        for f in sorted(self._templates_dir.glob("*.json"), reverse=True):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                templates.append(Template.model_validate(data))
            except Exception as exc:
                logger.warning("Skipping invalid template %s: %s", f.name, exc)
        templates.sort(key=lambda t: t.created_at, reverse=True)
        return templates

    def delete_template(self, template_id: str) -> bool:
        """Delete a template.

        Args:
            template_id: Template to delete.

        Returns:
            True if deleted, False if not found.
        """
        path = self._templates_dir / f"{template_id}.json"
        if path.exists():
            path.unlink()
            logger.info("Deleted template %s", template_id[:8])
            return True
        return False

    # ------------------------------------------------------------------
    # Documents
    # ------------------------------------------------------------------

    def save_document(
        self,
        document: Document,
        pdf_data: Optional[bytes] = None,
    ) -> Path:
        """Save a document and optionally its PDF.

        Args:
            document: Document to persist.
            pdf_data: Raw PDF bytes to store alongside.

        Returns:
            Path to the document directory.
        """
        doc_dir = self._documents_dir / document.document_id
        doc_dir.mkdir(parents=True, exist_ok=True)

        json_path = doc_dir / "document.json"
        json_path.write_text(
            document.model_dump_json(indent=2, by_alias=True),
            encoding="utf-8",
        )

        if pdf_data is not None:
            pdf_path = doc_dir / "source.pdf"
            pdf_path.write_bytes(pdf_data)
            document.pdf_path = str(pdf_path)

        logger.info("Saved document %s (%s)", document.title, document.document_id[:8])
        return doc_dir

    def load_document(self, document_id: str) -> Document:
        """Load a document by ID.

        Args:
            document_id: Unique document identifier.

        Returns:
            The Document.

        Raises:
            FileNotFoundError: If the document doesn't exist.
        """
        json_path = self._documents_dir / document_id / "document.json"
        if not json_path.exists():
            raise FileNotFoundError(f"Document not found: {document_id}")
        data = json.loads(json_path.read_text(encoding="utf-8"))
        return Document.model_validate(data)

    def get_document_pdf(self, document_id: str) -> Optional[bytes]:
        """Read the source PDF for a document.

        Args:
            document_id: Document ID.

        Returns:
            PDF bytes or None if no PDF stored.
        """
        pdf_path = self._documents_dir / document_id / "source.pdf"
        if pdf_path.exists():
            return pdf_path.read_bytes()
        return None

    def list_documents(
        self,
        status: Optional[DocumentStatus] = None,
    ) -> list[Document]:
        """List documents, optionally filtered by status.

        Args:
            status: Filter to this status (None = all).

        Returns:
            List of Documents sorted by creation date (newest first).
        """
        documents = []
        for doc_dir in self._documents_dir.iterdir():
            json_path = doc_dir / "document.json"
            if not json_path.exists():
                continue
            try:
                data = json.loads(json_path.read_text(encoding="utf-8"))
                doc = Document.model_validate(data)
                if status is None or doc.status == status:
                    documents.append(doc)
            except Exception as exc:
                logger.warning("Skipping invalid document %s: %s", doc_dir.name, exc)
        documents.sort(key=lambda d: d.created_at, reverse=True)
        return documents

    def delete_document(self, document_id: str) -> bool:
        """Delete a document and its files.

        Args:
            document_id: Document to delete.

        Returns:
            True if deleted, False if not found.
        """
        doc_dir = self._documents_dir / document_id
        if doc_dir.exists():
            shutil.rmtree(doc_dir)
            logger.info("Deleted document %s", document_id[:8])
            return True
        return False

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def append_audit(self, entry: AuditEntry) -> None:
        """Append an audit entry to the log (JSONL format).

        Args:
            entry: Audit entry to record.
        """
        log_path = self._audit_dir / f"{entry.document_id}.jsonl"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(entry.model_dump_json(by_alias=True) + "\n")

    def get_audit_trail(self, document_id: str) -> list[AuditEntry]:
        """Load the full audit trail for a document.

        Args:
            document_id: Document ID.

        Returns:
            Chronological list of audit entries.
        """
        log_path = self._audit_dir / f"{document_id}.jsonl"
        if not log_path.exists():
            return []

        entries = []
        for line in log_path.read_text(encoding="utf-8").strip().splitlines():
            try:
                entries.append(AuditEntry.model_validate_json(line))
            except Exception:
                continue
        return sorted(entries, key=lambda e: e.timestamp)

    # ------------------------------------------------------------------
    # Public keys (cache for verification)
    # ------------------------------------------------------------------

    def store_public_key(self, fingerprint: str, armor: str) -> Path:
        """Cache a public key for future verification.

        Args:
            fingerprint: 40-char hex PGP fingerprint.
            armor: ASCII-armored public key.

        Returns:
            Path to the stored key file.
        """
        path = self._keys_dir / f"{fingerprint}.asc"
        path.write_text(armor, encoding="utf-8")
        return path

    def get_public_key(self, fingerprint: str) -> Optional[str]:
        """Retrieve a cached public key.

        Args:
            fingerprint: PGP fingerprint to look up.

        Returns:
            ASCII-armored public key or None.
        """
        path = self._keys_dir / f"{fingerprint}.asc"
        if path.exists():
            return path.read_text(encoding="utf-8")
        return None

    def list_public_keys(self) -> list[str]:
        """List all cached key fingerprints."""
        return [f.stem for f in self._keys_dir.glob("*.asc")]
