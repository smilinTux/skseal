"""SKSeal ↔ SKComms P2P signing transport.

Delivers document signing requests and responses over sovereign SKComms
transport — no centralized server in the signing flow.

Flow:
    Peer A (requestor)                         Peer B (signer)
    ─────────────────                          ───────────────
    send_signing_request()  ──SIGNING_REQUEST──►  receive_signing_requests()
                                                   sign locally (pgpy / OpenPGP.js)
    receive_signing_responses() ◄─SIGNING_RESPONSE── send_signing_response()
    apply_signing_response()

The payload is JSON-encoded and carried as the SKComms envelope content.
The envelope MessageType is SIGNING_REQUEST or SIGNING_RESPONSE so
routers/filters can handle signing traffic separately from chat.

All crypto lives on the signers' machines. The transport only moves
hashes and signatures — never private key material.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from .models import (
    AuditAction,
    AuditEntry,
    Document,
    DocumentStatus,
    SignatureRecord,
    Signer,
    SignerStatus,
)
from .store import DocumentStore

if TYPE_CHECKING:
    from skcomms import SKComms
    from skcomms.models import MessageEnvelope

logger = logging.getLogger("skseal.skcomms_transport")


# ---------------------------------------------------------------------------
# Payload models (plain dicts — no extra deps)
# ---------------------------------------------------------------------------

def _signing_request_payload(
    document: Document,
    signer: Signer,
    sender_fingerprint: str,
    request_id: Optional[str] = None,
    expire_seconds: int = 86400,
) -> dict:
    """Build a SIGNING_REQUEST payload dict.

    Args:
        document: The document requiring a signature.
        signer: The Signer record for the intended recipient.
        sender_fingerprint: PGP fingerprint of the requestor.
        request_id: Idempotency key; auto-generated if None.
        expire_seconds: Seconds until the request expires (default 24 h).

    Returns:
        JSON-serialisable dict ready to embed in an SKComms envelope.
    """
    if request_id is None:
        request_id = str(uuid.uuid4())

    now = datetime.now(timezone.utc)
    expires_at = datetime.fromtimestamp(
        now.timestamp() + expire_seconds, tz=timezone.utc
    )

    return {
        "request_id": request_id,
        "document_id": document.document_id,
        "document_title": document.title,
        "document_hash": document.pdf_hash or "",
        "sender_fingerprint": sender_fingerprint,
        "signer_fingerprint": signer.fingerprint,
        "signer_id": signer.signer_id,
        "signer_name": signer.name,
        "signer_role": signer.role.value,
        "field_names": [f.name for f in document.fields if f.role == signer.role.value],
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
    }


def _signing_response_payload(
    request_id: str,
    document_id: str,
    signer_id: str,
    signer_fingerprint: str,
    document_hash: str,
    signature_armor: str,
    field_values: Optional[dict] = None,
) -> dict:
    """Build a SIGNING_RESPONSE payload dict.

    Args:
        request_id: The request_id from the original SIGNING_REQUEST.
        document_id: Document that was signed.
        signer_id: Signer record ID within the document.
        signer_fingerprint: PGP fingerprint used to sign.
        document_hash: SHA-256 hash that was signed (for cross-check).
        signature_armor: ASCII-armored PGP signature.
        field_values: Filled form field values (signer-completed fields).

    Returns:
        JSON-serialisable dict ready to embed in an SKComms envelope.
    """
    return {
        "request_id": request_id,
        "document_id": document_id,
        "signer_id": signer_id,
        "signer_fingerprint": signer_fingerprint,
        "document_hash": document_hash,
        "signature_armor": signature_armor,
        "field_values": field_values or {},
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Transport class
# ---------------------------------------------------------------------------

class SealSKCommsTransport:
    """Wire SKSeal document signing through SKComms P2P transports.

    Stateless helper — all persistent state lives in the DocumentStore.

    Args:
        store: DocumentStore instance (or None to use the default).
        identity_fingerprint: PGP fingerprint of the local agent/user.
    """

    def __init__(
        self,
        store: Optional[DocumentStore] = None,
        identity_fingerprint: str = "",
    ):
        self._store = store or DocumentStore()
        self._fingerprint = identity_fingerprint

    # ------------------------------------------------------------------
    # Peer A: send a signing request
    # ------------------------------------------------------------------

    def send_signing_request(
        self,
        skcomms: "SKComms",
        document_id: str,
        signer_fingerprint: str,
        *,
        sender_fingerprint: Optional[str] = None,
        request_id: Optional[str] = None,
        expire_seconds: int = 86400,
    ) -> dict:
        """Send a signing request to a peer via SKComms.

        Loads the document, finds the signer by fingerprint, serialises
        a SIGNING_REQUEST payload, and delivers it via SKComms.

        Args:
            skcomms: Live SKComms instance.
            document_id: ID of the document to sign.
            signer_fingerprint: PGP fingerprint of the intended signer.
            sender_fingerprint: Fingerprint of the local identity
                (defaults to self._fingerprint).
            request_id: Idempotency key; auto-generated if None.
            expire_seconds: Seconds until the request expires.

        Returns:
            Dict with keys: request_id, delivered, transport, error.

        Raises:
            FileNotFoundError: If the document does not exist.
            ValueError: If the signer is not found in the document.
        """
        document = self._store.load_document(document_id)

        signer = self._find_signer(document, signer_fingerprint)
        if signer is None:
            raise ValueError(
                f"No signer with fingerprint '{signer_fingerprint}' "
                f"in document '{document.title}'"
            )

        fp = sender_fingerprint or self._fingerprint
        payload = _signing_request_payload(
            document=document,
            signer=signer,
            sender_fingerprint=fp,
            request_id=request_id,
            expire_seconds=expire_seconds,
        )

        try:
            from skcomms.models import MessageType, Urgency

            report = skcomms.send(
                recipient=signer_fingerprint,
                message=json.dumps(payload),
                message_type=MessageType.SIGNING_REQUEST,
                urgency=Urgency.HIGH,
                thread_id=document_id,
            )
            delivered = report.delivered
            transport = report.transport
            error = report.error
        except Exception as exc:
            logger.error("Failed to send signing request: %s", exc)
            delivered = False
            transport = None
            error = str(exc)

        # Audit
        try:
            self._store.append_audit(
                AuditEntry(
                    document_id=document_id,
                    action=AuditAction.SENT,
                    actor_fingerprint=fp,
                    details=(
                        f"P2P signing request sent to {signer_fingerprint[:16]}… "
                        f"via SKComms (delivered={delivered})"
                    ),
                )
            )
        except Exception as exc:
            logger.debug("Audit append failed: %s", exc)

        logger.info(
            "Signing request [%s] sent to %s, delivered=%s via %s",
            payload["request_id"][:8],
            signer_fingerprint[:16],
            delivered,
            transport,
        )

        return {
            "request_id": payload["request_id"],
            "delivered": delivered,
            "transport": transport,
            "error": error,
        }

    # ------------------------------------------------------------------
    # Peer B: receive signing requests
    # ------------------------------------------------------------------

    def receive_signing_requests(
        self, skcomms: "SKComms"
    ) -> list[dict]:
        """Poll SKComms inbox for incoming SIGNING_REQUEST envelopes.

        Returns the parsed payload dicts — does NOT auto-sign. The
        caller decides whether to sign (human approval or auto-sign).

        Args:
            skcomms: Live SKComms instance.

        Returns:
            List of decoded signing request payload dicts.
        """
        try:
            from skcomms.models import MessageType

            envelopes = skcomms.receive()
        except Exception as exc:
            logger.warning("Failed to receive from SKComms: %s", exc)
            return []

        requests = []
        for env in envelopes:
            try:
                if env.payload.content_type != MessageType.SIGNING_REQUEST:
                    continue
                payload = json.loads(env.payload.content)
                payload["_envelope_id"] = env.envelope_id
                payload["_sender"] = env.sender
                requests.append(payload)
            except Exception as exc:
                logger.warning("Malformed signing request envelope: %s", exc)

        return requests

    # ------------------------------------------------------------------
    # Peer B: sign a request and send the response
    # ------------------------------------------------------------------

    def respond_to_signing_request(
        self,
        skcomms: "SKComms",
        request_payload: dict,
        private_key_armor: str,
        passphrase: str,
        field_values: Optional[dict] = None,
    ) -> dict:
        """Sign the document hash and deliver the response via SKComms.

        This is the Peer B side. Peer B receives a SIGNING_REQUEST,
        calls this method to produce and deliver a SIGNING_RESPONSE.
        Keys never leave the signer's machine — only the hash and
        the resulting signature travel over SKComms.

        Args:
            skcomms: Live SKComms instance.
            request_payload: Decoded SIGNING_REQUEST payload dict.
            private_key_armor: ASCII-armored PGP private key (stays local).
            passphrase: Passphrase to unlock the private key.
            field_values: Form field values the signer is completing.

        Returns:
            Dict with keys: request_id, signed, delivered, transport, error.
        """
        from .engine import SealEngine

        engine = SealEngine()

        request_id: str = request_payload["request_id"]
        document_id: str = request_payload["document_id"]
        signer_id: str = request_payload["signer_id"]
        document_hash: str = request_payload["document_hash"]
        requestor_fingerprint: str = request_payload.get("sender_fingerprint", "")

        if not document_hash:
            return {
                "request_id": request_id,
                "signed": False,
                "delivered": False,
                "transport": None,
                "error": "Request payload missing document_hash",
            }

        # Sign the document hash locally — key never leaves this machine
        try:
            signature_armor = engine._pgp_sign(
                document_hash.encode("utf-8"), private_key_armor, passphrase
            )
            signer_fingerprint = engine._extract_fingerprint(private_key_armor)
        except Exception as exc:
            logger.error("PGP signing failed: %s", exc)
            return {
                "request_id": request_id,
                "signed": False,
                "delivered": False,
                "transport": None,
                "error": f"Signing failed: {exc}",
            }

        response = _signing_response_payload(
            request_id=request_id,
            document_id=document_id,
            signer_id=signer_id,
            signer_fingerprint=signer_fingerprint,
            document_hash=document_hash,
            signature_armor=signature_armor,
            field_values=field_values,
        )

        # Deliver response back to requestor via SKComms
        delivered = False
        transport = None
        error = None
        try:
            from skcomms.models import MessageType, Urgency

            report = skcomms.send(
                recipient=requestor_fingerprint or request_payload.get("_sender", ""),
                message=json.dumps(response),
                message_type=MessageType.SIGNING_RESPONSE,
                urgency=Urgency.HIGH,
                thread_id=document_id,
                in_reply_to=request_payload.get("_envelope_id"),
            )
            delivered = report.delivered
            transport = report.transport
            error = report.error
        except Exception as exc:
            logger.error("Failed to deliver signing response: %s", exc)
            error = str(exc)

        logger.info(
            "Signing response [%s] sent to %s, delivered=%s via %s",
            request_id[:8],
            requestor_fingerprint[:16] if requestor_fingerprint else "unknown",
            delivered,
            transport,
        )

        return {
            "request_id": request_id,
            "signed": True,
            "signer_fingerprint": signer_fingerprint,
            "delivered": delivered,
            "transport": transport,
            "error": error,
        }

    # ------------------------------------------------------------------
    # Peer A: receive and apply signing responses
    # ------------------------------------------------------------------

    def receive_signing_responses(
        self, skcomms: "SKComms"
    ) -> list[dict]:
        """Poll SKComms inbox for incoming SIGNING_RESPONSE envelopes.

        Returns decoded response payload dicts.

        Args:
            skcomms: Live SKComms instance.

        Returns:
            List of decoded signing response payload dicts.
        """
        try:
            from skcomms.models import MessageType

            envelopes = skcomms.receive()
        except Exception as exc:
            logger.warning("Failed to receive from SKComms: %s", exc)
            return []

        responses = []
        for env in envelopes:
            try:
                if env.payload.content_type != MessageType.SIGNING_RESPONSE:
                    continue
                payload = json.loads(env.payload.content)
                payload["_envelope_id"] = env.envelope_id
                payload["_sender"] = env.sender
                responses.append(payload)
            except Exception as exc:
                logger.warning("Malformed signing response envelope: %s", exc)

        return responses

    def apply_signing_response(
        self,
        response_payload: dict,
        *,
        public_key_armor: Optional[str] = None,
        verify: bool = True,
    ) -> Document:
        """Apply an incoming SIGNING_RESPONSE to the stored document.

        Validates the signature (if public_key_armor provided), records
        the SignatureRecord, updates the signer's status, and saves.

        Args:
            response_payload: Decoded SIGNING_RESPONSE payload dict.
            public_key_armor: Signer's public key for verification.
                Skip verification if None and verify=False.
            verify: Whether to verify the signature before applying.

        Returns:
            Updated Document.

        Raises:
            ValueError: If signature verification fails or signer not found.
            FileNotFoundError: If the document is not found.
        """
        from .engine import SealEngine

        engine = SealEngine()

        document_id: str = response_payload["document_id"]
        signer_id: str = response_payload["signer_id"]
        signer_fingerprint: str = response_payload["signer_fingerprint"]
        document_hash: str = response_payload["document_hash"]
        signature_armor: str = response_payload["signature_armor"]
        field_values: dict = response_payload.get("field_values", {})
        signed_at_str: str = response_payload.get("signed_at", "")

        document = self._store.load_document(document_id)

        # Find the signer
        signer = self._find_signer_by_id(document, signer_id)
        if signer is None:
            raise ValueError(f"Signer {signer_id} not found in document")

        if signer.status == SignerStatus.SIGNED:
            logger.info("Signer %s already signed — ignoring duplicate response", signer_id[:8])
            return document

        # Verify the signature if we have the public key
        if verify and public_key_armor:
            valid = engine._pgp_verify(
                document_hash.encode("utf-8"),
                signature_armor,
                public_key_armor,
            )
            if not valid:
                raise ValueError(
                    f"Signature verification failed for signer {signer_fingerprint[:16]}"
                )
        elif verify and not public_key_armor:
            # Try to get from key cache
            cached_key = self._store.get_public_key(signer_fingerprint)
            if cached_key:
                valid = engine._pgp_verify(
                    document_hash.encode("utf-8"),
                    signature_armor,
                    cached_key,
                )
                if not valid:
                    raise ValueError(
                        f"Signature verification failed for signer {signer_fingerprint[:16]}"
                    )
            else:
                logger.warning(
                    "No public key for %s — skipping signature verification",
                    signer_fingerprint[:16],
                )

        # Parse signed_at
        try:
            signed_at = datetime.fromisoformat(signed_at_str)
        except Exception:
            signed_at = datetime.now(timezone.utc)

        # Record the signature
        record = SignatureRecord(
            document_id=document_id,
            signer_id=signer_id,
            fingerprint=signer_fingerprint,
            document_hash=document_hash,
            signature_armor=signature_armor,
            signed_at=signed_at,
            user_agent="skcomms-p2p",
            field_values=field_values,
        )
        document.signatures.append(record)

        # Update signer status
        signer.status = SignerStatus.SIGNED
        signer.signed_at = signed_at
        signer.fingerprint = signer_fingerprint

        # Audit
        document.audit_trail.append(
            AuditEntry(
                document_id=document_id,
                action=AuditAction.SIGNED,
                actor_fingerprint=signer_fingerprint,
                actor_name=signer.name,
                timestamp=signed_at,
                details=f"P2P signature received via SKComms from {signer_fingerprint[:16]}…",
            )
        )

        # Check completion
        if document.is_complete:
            document.status = DocumentStatus.COMPLETED
            document.completed_at = datetime.now(timezone.utc)
            document.audit_trail.append(
                AuditEntry(
                    document_id=document_id,
                    action=AuditAction.COMPLETED,
                    timestamp=document.completed_at,
                    details="All signers have signed via P2P SKComms transport.",
                )
            )
        else:
            document.status = DocumentStatus.PARTIALLY_SIGNED

        self._store.save_document(document)
        logger.info(
            "Applied P2P signature from %s to document %s (status: %s)",
            signer_fingerprint[:16],
            document_id[:8],
            document.status.value,
        )
        return document

    # ------------------------------------------------------------------
    # Convenience: poll inbox and process all responses in one call
    # ------------------------------------------------------------------

    def poll_and_apply_responses(
        self,
        skcomms: "SKComms",
        *,
        verify: bool = True,
    ) -> list[dict]:
        """Poll for signing responses and apply them all to documents.

        Convenience wrapper for the Peer A side. Typically called
        periodically (e.g. from a cron or MCP tool).

        Args:
            skcomms: Live SKComms instance.
            verify: Whether to verify signatures before applying.

        Returns:
            List of result dicts:
              {request_id, document_id, applied, document_status, error}
        """
        responses = self.receive_signing_responses(skcomms)
        results = []
        for resp in responses:
            result: dict = {
                "request_id": resp.get("request_id", ""),
                "document_id": resp.get("document_id", ""),
                "applied": False,
                "document_status": None,
                "error": None,
            }
            try:
                doc = self.apply_signing_response(resp, verify=verify)
                result["applied"] = True
                result["document_status"] = doc.status.value
            except Exception as exc:
                result["error"] = str(exc)
                logger.error("Failed to apply signing response: %s", exc)
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_signer(document: Document, fingerprint: str) -> Optional[Signer]:
        """Find a signer in a document by PGP fingerprint (prefix match)."""
        fingerprint_upper = fingerprint.upper()
        for s in document.signers:
            if s.fingerprint.upper().startswith(fingerprint_upper):
                return s
        return None

    @staticmethod
    def _find_signer_by_id(document: Document, signer_id: str) -> Optional[Signer]:
        """Find a signer in a document by signer_id."""
        for s in document.signers:
            if s.signer_id == signer_id:
                return s
        return None
