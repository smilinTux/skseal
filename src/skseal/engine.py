"""SKSeal signing engine — PGP-backed document signing.

Handles the cryptographic operations: hashing documents, creating PGP
detached signatures, verifying signatures, and managing the multi-signer
workflow. Uses CapAuth's CryptoBackend for PGP operations so the same
key infrastructure powers identity AND document signing.

Keys never leave the signer's device. The engine operates on hashes
and signatures — never on raw private key material at rest.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pgpy

from .models import (
    AuditAction,
    AuditEntry,
    Document,
    DocumentStatus,
    SignatureRecord,
    Signer,
    SignerStatus,
)

logger = logging.getLogger("skseal.engine")


class SealEngine:
    """Core signing and verification engine.

    Stateless — all state lives in the Document model. The engine
    takes documents in, performs crypto, and returns updated documents.
    """

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    @staticmethod
    def hash_file(path: Path) -> str:
        """Compute SHA-256 hash of a file.

        Args:
            path: Path to the file.

        Returns:
            Hex-encoded SHA-256 digest.

        Raises:
            FileNotFoundError: If the file doesn't exist.
        """
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        """Compute SHA-256 hash of raw bytes.

        Args:
            data: Bytes to hash.

        Returns:
            Hex-encoded SHA-256 digest.
        """
        return hashlib.sha256(data).hexdigest()

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign_document(
        self,
        document: Document,
        signer_id: str,
        private_key_armor: str,
        passphrase: str,
        pdf_data: Optional[bytes] = None,
        pdf_path: Optional[Path] = None,
        field_values: Optional[dict[str, str]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Document:
        """Sign a document with a signer's PGP key.

        Creates a detached PGP signature over the document's SHA-256 hash,
        records the signature, updates the signer's status, and appends
        audit trail entries.

        Args:
            document: The document to sign.
            signer_id: ID of the signer within the document.
            private_key_armor: ASCII-armored PGP private key.
            passphrase: Passphrase to unlock the private key.
            pdf_data: Raw PDF bytes (provide this OR pdf_path).
            pdf_path: Path to the PDF file.
            field_values: Values the signer filled in.
            ip_address: Signer's IP for audit.
            user_agent: Signer's client info for audit.

        Returns:
            Updated Document with signature and audit entries.

        Raises:
            ValueError: If signer not found or document not signable.
            RuntimeError: If PGP signing fails.
        """
        signer = self._get_signer(document, signer_id)
        self._validate_signing_state(document, signer)

        doc_hash = self._resolve_hash(document, pdf_data, pdf_path)

        signature_armor = self._pgp_sign(
            doc_hash.encode("utf-8"), private_key_armor, passphrase
        )
        fingerprint = self._extract_fingerprint(private_key_armor)

        now = datetime.now(timezone.utc)

        record = SignatureRecord(
            document_id=document.document_id,
            signer_id=signer_id,
            fingerprint=fingerprint,
            document_hash=doc_hash,
            signature_armor=signature_armor,
            signed_at=now,
            ip_address=ip_address,
            user_agent=user_agent,
            field_values=field_values or {},
        )
        document.signatures.append(record)

        signer.status = SignerStatus.SIGNED
        signer.signed_at = now
        signer.fingerprint = fingerprint

        document.audit_trail.append(
            AuditEntry(
                document_id=document.document_id,
                action=AuditAction.SIGNED,
                actor_fingerprint=fingerprint,
                actor_name=signer.name,
                timestamp=now,
                details=f"Signed with key {fingerprint[:16]}...",
                ip_address=ip_address,
            )
        )

        if document.is_complete:
            document.status = DocumentStatus.COMPLETED
            document.completed_at = now
            document.audit_trail.append(
                AuditEntry(
                    document_id=document.document_id,
                    action=AuditAction.COMPLETED,
                    timestamp=now,
                    details="All signers have signed.",
                )
            )
        else:
            document.status = DocumentStatus.PARTIALLY_SIGNED

        logger.info(
            "Signer %s (%s) signed document %s",
            signer.name,
            fingerprint[:16],
            document.document_id[:8],
        )
        return document

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_signature(
        self,
        record: SignatureRecord,
        public_key_armor: str,
        pdf_data: Optional[bytes] = None,
        pdf_path: Optional[Path] = None,
    ) -> bool:
        """Verify a single signature record.

        Checks that:
        1. The PGP signature is cryptographically valid
        2. The document hash matches (if PDF provided)

        Args:
            record: The signature record to verify.
            public_key_armor: Signer's ASCII-armored public key.
            pdf_data: Current PDF bytes for hash comparison.
            pdf_path: Path to current PDF for hash comparison.

        Returns:
            True if the signature is valid.
        """
        if pdf_data is not None:
            current_hash = self.hash_bytes(pdf_data)
            if current_hash != record.document_hash:
                logger.warning(
                    "Hash mismatch: document has been modified since signing"
                )
                return False
        elif pdf_path is not None:
            current_hash = self.hash_file(pdf_path)
            if current_hash != record.document_hash:
                logger.warning(
                    "Hash mismatch: document has been modified since signing"
                )
                return False

        return self._pgp_verify(
            record.document_hash.encode("utf-8"),
            record.signature_armor,
            public_key_armor,
        )

    def verify_document(
        self,
        document: Document,
        public_keys: dict[str, str],
        pdf_data: Optional[bytes] = None,
        pdf_path: Optional[Path] = None,
    ) -> dict[str, bool]:
        """Verify all signatures on a document.

        Args:
            document: The document to verify.
            public_keys: Mapping of fingerprint -> ASCII-armored public key.
            pdf_data: Current PDF bytes.
            pdf_path: Path to current PDF.

        Returns:
            Dict mapping signer_id -> verification result.
        """
        results: dict[str, bool] = {}
        for record in document.signatures:
            pubkey = public_keys.get(record.fingerprint)
            if pubkey is None:
                logger.warning(
                    "No public key for fingerprint %s", record.fingerprint[:16]
                )
                results[record.signer_id] = False
                continue

            results[record.signer_id] = self.verify_signature(
                record, pubkey, pdf_data=pdf_data, pdf_path=pdf_path
            )
        return results

    # ------------------------------------------------------------------
    # Seal (final tamper-evident envelope)
    # ------------------------------------------------------------------

    def seal_document(
        self,
        document: Document,
        sealing_key_armor: str,
        passphrase: str,
    ) -> str:
        """Create a tamper-evident seal over the complete document.

        The seal is a PGP signature over a JSON digest that includes
        the document hash, all signature records, and the audit trail.
        Anyone with the sealing key's public counterpart can verify
        the entire package hasn't been tampered with.

        Args:
            document: A completed document.
            sealing_key_armor: ASCII-armored private sealing key.
            passphrase: Passphrase for the sealing key.

        Returns:
            ASCII-armored PGP signature (the seal).

        Raises:
            ValueError: If document is not completed.
        """
        if document.status != DocumentStatus.COMPLETED:
            raise ValueError("Cannot seal an incomplete document")

        digest = self._build_seal_digest(document)
        return self._pgp_sign(digest, sealing_key_armor, passphrase)

    def verify_seal(
        self,
        document: Document,
        seal_armor: str,
        sealing_pubkey_armor: str,
    ) -> bool:
        """Verify a document seal.

        Args:
            document: The document to verify.
            seal_armor: The seal signature.
            sealing_pubkey_armor: Public key of the sealing authority.

        Returns:
            True if the seal is valid.
        """
        digest = self._build_seal_digest(document)
        return self._pgp_verify(digest, seal_armor, sealing_pubkey_armor)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_signer(document: Document, signer_id: str) -> Signer:
        """Find a signer by ID within a document."""
        for s in document.signers:
            if s.signer_id == signer_id:
                return s
        raise ValueError(f"Signer {signer_id} not found in document")

    @staticmethod
    def _validate_signing_state(document: Document, signer: Signer) -> None:
        """Ensure the document and signer are in a signable state."""
        if document.status == DocumentStatus.VOIDED:
            raise ValueError("Cannot sign a voided document")
        if document.status == DocumentStatus.COMPLETED:
            raise ValueError("Document is already completed")
        if signer.status == SignerStatus.SIGNED:
            raise ValueError(f"Signer {signer.name} has already signed")
        if signer.status == SignerStatus.DECLINED:
            raise ValueError(f"Signer {signer.name} has declined")

    def _resolve_hash(
        self,
        document: Document,
        pdf_data: Optional[bytes],
        pdf_path: Optional[Path],
    ) -> str:
        """Get the document hash from provided data or stored value."""
        if pdf_data is not None:
            return self.hash_bytes(pdf_data)
        if pdf_path is not None:
            return self.hash_file(pdf_path)
        if document.pdf_hash:
            return document.pdf_hash
        raise ValueError("No PDF data, path, or stored hash available")

    @staticmethod
    def _pgp_sign(data: bytes, private_key_armor: str, passphrase: str) -> str:
        """Create a PGP signature over data.

        Args:
            data: Bytes to sign (typically a hash string encoded to bytes).
            private_key_armor: ASCII-armored private key.
            passphrase: Key passphrase.

        Returns:
            ASCII-armored PGP signed message.

        Raises:
            RuntimeError: If signing fails.
        """
        try:
            key, _ = pgpy.PGPKey.from_blob(private_key_armor)
            with key.unlock(passphrase):
                message = pgpy.PGPMessage.new(data, cleartext=False)
                sig = key.sign(message)
                message |= sig
            return str(message)
        except Exception as exc:
            raise RuntimeError(f"PGP signing failed: {exc}") from exc

    @staticmethod
    def _pgp_verify(
        data: bytes, signature_armor: str, public_key_armor: str
    ) -> bool:
        """Verify a PGP signature.

        Args:
            data: Original bytes that were signed.
            signature_armor: ASCII-armored PGP signed message.
            public_key_armor: Signer's ASCII-armored public key.

        Returns:
            True if valid.
        """
        try:
            pub_key, _ = pgpy.PGPKey.from_blob(public_key_armor)
            signed_msg = pgpy.PGPMessage.from_blob(signature_armor)

            embedded = signed_msg.message
            if isinstance(embedded, str):
                embedded = embedded.encode("utf-8")
            if embedded != data:
                return False

            verification = pub_key.verify(signed_msg)
            return bool(verification)
        except Exception:
            return False

    @staticmethod
    def _extract_fingerprint(key_armor: str) -> str:
        """Extract PGP fingerprint from an armored key."""
        key, _ = pgpy.PGPKey.from_blob(key_armor)
        return str(key.fingerprint).replace(" ", "")

    @staticmethod
    def _build_seal_digest(document: Document) -> bytes:
        """Build a deterministic digest of the document for sealing.

        Includes: document hash + all signature records + audit trail.
        Sorted JSON ensures reproducible digest across platforms.
        """
        payload = {
            "document_id": document.document_id,
            "pdf_hash": document.pdf_hash,
            "signatures": [
                {
                    "signer_id": r.signer_id,
                    "fingerprint": r.fingerprint,
                    "document_hash": r.document_hash,
                    "signed_at": r.signed_at.isoformat(),
                }
                for r in sorted(
                    document.signatures, key=lambda r: r.signed_at
                )
            ],
            "completed_at": (
                document.completed_at.isoformat()
                if document.completed_at
                else None
            ),
        }
        return json.dumps(payload, sort_keys=True).encode("utf-8")
