"""Tests for SKSeal ↔ SKComms P2P signing transport.

These tests use a mock SKComms so no real network transport is required.
The crypto is real (pgpy), so signing and verification are exercised end-to-end.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from skseal.engine import SealEngine
from skseal.models import Document, DocumentStatus, Signer, SignerStatus
from skseal.skcomms_transport import (
    SealSKCommsTransport,
    _signing_request_payload,
    _signing_response_payload,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

PASSPHRASE = "test-passphrase-123"


def _make_mock_skcomms(envelopes=None):
    """Return a mock SKComms with send() and receive() stubbed."""
    skcomms = MagicMock()

    # send() returns a DeliveryReport-like object
    report = MagicMock()
    report.delivered = True
    report.transport = "file"
    report.error = None
    skcomms.send.return_value = report

    # receive() returns provided envelopes (default empty)
    skcomms.receive.return_value = envelopes or []
    return skcomms


def _make_signing_request_envelope(payload: dict):
    """Build a mock MessageEnvelope for a SIGNING_REQUEST."""
    env = MagicMock()
    env.envelope_id = str(uuid.uuid4())
    env.sender = payload.get("sender_fingerprint", "ABCD")

    from skcomms.models import MessageType  # may not be importable in test env

    env.payload.content_type = MessageType.SIGNING_REQUEST
    env.payload.content = json.dumps(payload)
    return env


def _make_signing_response_envelope(payload: dict):
    """Build a mock MessageEnvelope for a SIGNING_RESPONSE."""
    env = MagicMock()
    env.envelope_id = str(uuid.uuid4())
    env.sender = payload.get("signer_fingerprint", "ABCD")

    from skcomms.models import MessageType

    env.payload.content_type = MessageType.SIGNING_RESPONSE
    env.payload.content = json.dumps(payload)
    return env


# ---------------------------------------------------------------------------
# Payload helpers
# ---------------------------------------------------------------------------

class TestPayloadBuilders:
    def test_signing_request_payload_structure(self, tmp_store, chef_keys, lumina_keys):
        priv_chef, pub_chef = chef_keys
        priv_lumina, pub_lumina = lumina_keys

        engine = SealEngine()
        chef_fp = engine._extract_fingerprint(priv_chef)
        lumina_fp = engine._extract_fingerprint(priv_lumina)

        signer = Signer(name="Lumina", fingerprint=lumina_fp)
        document = Document(
            title="Test NDA",
            pdf_hash="abc123",
            signers=[signer],
        )

        payload = _signing_request_payload(
            document=document,
            signer=signer,
            sender_fingerprint=chef_fp,
        )

        assert payload["document_id"] == document.document_id
        assert payload["document_title"] == "Test NDA"
        assert payload["document_hash"] == "abc123"
        assert payload["sender_fingerprint"] == chef_fp
        assert payload["signer_fingerprint"] == lumina_fp
        assert payload["signer_id"] == signer.signer_id
        assert "request_id" in payload
        assert "expires_at" in payload
        assert "created_at" in payload

    def test_signing_response_payload_structure(self):
        request_id = str(uuid.uuid4())
        payload = _signing_response_payload(
            request_id=request_id,
            document_id="doc-123",
            signer_id="signer-456",
            signer_fingerprint="ABCDEF1234567890",
            document_hash="deadbeef",
            signature_armor="-----BEGIN PGP SIGNED MESSAGE-----\nfake\n-----END...",
            field_values={"name": "Alice"},
        )

        assert payload["request_id"] == request_id
        assert payload["document_id"] == "doc-123"
        assert payload["signer_fingerprint"] == "ABCDEF1234567890"
        assert payload["signature_armor"].startswith("-----BEGIN PGP")
        assert payload["field_values"] == {"name": "Alice"}
        assert "signed_at" in payload


# ---------------------------------------------------------------------------
# SealSKCommsTransport: send_signing_request
# ---------------------------------------------------------------------------

class TestSendSigningRequest:
    def test_sends_to_correct_recipient(self, tmp_store, chef_keys, lumina_keys):
        priv_chef, pub_chef = chef_keys
        priv_lumina, pub_lumina = lumina_keys

        engine = SealEngine()
        chef_fp = engine._extract_fingerprint(priv_chef)
        lumina_fp = engine._extract_fingerprint(priv_lumina)

        signer = Signer(name="Lumina", fingerprint=lumina_fp)
        document = Document(title="NDA", pdf_hash="hash1", signers=[signer])
        tmp_store.save_document(document)

        skcomms = _make_mock_skcomms()
        transport = SealSKCommsTransport(store=tmp_store, identity_fingerprint=chef_fp)

        result = transport.send_signing_request(
            skcomms=skcomms,
            document_id=document.document_id,
            signer_fingerprint=lumina_fp,
            sender_fingerprint=chef_fp,
        )

        assert result["delivered"] is True
        assert result["transport"] == "file"
        assert result["error"] is None
        assert "request_id" in result

        # Verify SKComms was called with the right recipient and type
        call_kwargs = skcomms.send.call_args
        from skcomms.models import MessageType
        assert call_kwargs.kwargs["recipient"] == lumina_fp
        assert call_kwargs.kwargs["message_type"] == MessageType.SIGNING_REQUEST
        payload = json.loads(call_kwargs.kwargs["message"])
        assert payload["document_id"] == document.document_id
        assert payload["signer_fingerprint"] == lumina_fp

    def test_raises_if_document_not_found(self, tmp_store):
        skcomms = _make_mock_skcomms()
        transport = SealSKCommsTransport(store=tmp_store)

        with pytest.raises(FileNotFoundError):
            transport.send_signing_request(
                skcomms=skcomms,
                document_id="nonexistent-doc-id",
                signer_fingerprint="ABCDEF1234567890ABCDEF1234567890ABCDEF12",
            )

    def test_raises_if_signer_not_in_document(self, tmp_store):
        document = Document(title="NDA", pdf_hash="hash1", signers=[])
        tmp_store.save_document(document)

        skcomms = _make_mock_skcomms()
        transport = SealSKCommsTransport(store=tmp_store)

        with pytest.raises(ValueError, match="No signer"):
            transport.send_signing_request(
                skcomms=skcomms,
                document_id=document.document_id,
                signer_fingerprint="ABCDEF1234567890ABCDEF1234567890ABCDEF12",
            )


# ---------------------------------------------------------------------------
# SealSKCommsTransport: respond_to_signing_request (Peer B side)
# ---------------------------------------------------------------------------

class TestRespondToSigningRequest:
    def test_signs_and_delivers_response(self, tmp_store, lumina_keys):
        priv_lumina, pub_lumina = lumina_keys
        engine = SealEngine()
        lumina_fp = engine._extract_fingerprint(priv_lumina)
        chef_fp = "AABBCCDD" * 5  # fake requestor fingerprint

        document_hash = "abc123deadbeef"
        request_payload = {
            "request_id": str(uuid.uuid4()),
            "document_id": "doc-001",
            "document_hash": document_hash,
            "signer_id": "signer-001",
            "sender_fingerprint": chef_fp,
            "_envelope_id": str(uuid.uuid4()),
            "_sender": chef_fp,
        }

        skcomms = _make_mock_skcomms()
        transport = SealSKCommsTransport(store=tmp_store)

        result = transport.respond_to_signing_request(
            skcomms=skcomms,
            request_payload=request_payload,
            private_key_armor=priv_lumina,
            passphrase=PASSPHRASE,
        )

        assert result["signed"] is True
        assert result["delivered"] is True
        assert result["signer_fingerprint"] == lumina_fp

        # Verify the response was sent as SIGNING_RESPONSE
        from skcomms.models import MessageType
        call_kwargs = skcomms.send.call_args.kwargs
        assert call_kwargs["message_type"] == MessageType.SIGNING_RESPONSE
        assert call_kwargs["recipient"] == chef_fp

        # The response payload contains a valid PGP signature
        resp = json.loads(call_kwargs["message"])
        assert resp["document_hash"] == document_hash
        assert "-----BEGIN PGP" in resp["signature_armor"]
        assert resp["signer_fingerprint"] == lumina_fp

    def test_error_on_empty_document_hash(self, tmp_store, lumina_keys):
        priv_lumina, _ = lumina_keys
        request_payload = {
            "request_id": str(uuid.uuid4()),
            "document_id": "doc-002",
            "document_hash": "",   # empty!
            "signer_id": "signer-001",
            "sender_fingerprint": "AAAA",
        }

        skcomms = _make_mock_skcomms()
        transport = SealSKCommsTransport(store=tmp_store)

        result = transport.respond_to_signing_request(
            skcomms=skcomms,
            request_payload=request_payload,
            private_key_armor=priv_lumina,
            passphrase=PASSPHRASE,
        )

        assert result["signed"] is False
        assert "document_hash" in result["error"]


# ---------------------------------------------------------------------------
# SealSKCommsTransport: receive + apply signing response (Peer A side)
# ---------------------------------------------------------------------------

class TestApplySigningResponse:
    def _setup_document(self, tmp_store, signer_fp, document_hash):
        """Helper: save a document with one pending signer."""
        signer = Signer(name="Lumina", fingerprint=signer_fp)
        document = Document(
            title="Contract",
            pdf_hash=document_hash,
            status=DocumentStatus.PENDING,
            signers=[signer],
        )
        tmp_store.save_document(document)
        return document, signer

    def test_applies_valid_response(self, tmp_store, chef_keys, lumina_keys):
        priv_chef, pub_chef = chef_keys
        priv_lumina, pub_lumina = lumina_keys
        engine = SealEngine()
        lumina_fp = engine._extract_fingerprint(priv_lumina)

        document_hash = "sha256hashofcontract"
        document, signer = self._setup_document(tmp_store, lumina_fp, document_hash)

        # Simulate Peer B signing
        signature_armor = engine._pgp_sign(
            document_hash.encode("utf-8"), priv_lumina, PASSPHRASE
        )

        response_payload = {
            "request_id": str(uuid.uuid4()),
            "document_id": document.document_id,
            "signer_id": signer.signer_id,
            "signer_fingerprint": lumina_fp,
            "document_hash": document_hash,
            "signature_armor": signature_armor,
            "field_values": {"full_name": "Queen Lumina"},
            "signed_at": datetime.now(timezone.utc).isoformat(),
        }

        transport = SealSKCommsTransport(store=tmp_store)
        # Store the public key so verification works
        tmp_store.store_public_key(lumina_fp, pub_lumina)

        updated_doc = transport.apply_signing_response(response_payload, verify=True)

        assert updated_doc.status == DocumentStatus.COMPLETED
        assert updated_doc.signatures[0].fingerprint == lumina_fp
        assert updated_doc.signatures[0].field_values == {"full_name": "Queen Lumina"}
        # Signer status updated
        assert updated_doc.signers[0].status == SignerStatus.SIGNED

    def test_rejects_tampered_hash(self, tmp_store, chef_keys, lumina_keys):
        priv_chef, pub_chef = chef_keys
        priv_lumina, pub_lumina = lumina_keys
        engine = SealEngine()
        lumina_fp = engine._extract_fingerprint(priv_lumina)

        document_hash = "correcthash"
        document, signer = self._setup_document(tmp_store, lumina_fp, document_hash)
        tmp_store.store_public_key(lumina_fp, pub_lumina)

        # Sign a DIFFERENT hash (tamper simulation)
        signature_armor = engine._pgp_sign(
            b"wronghash", priv_lumina, PASSPHRASE
        )

        response_payload = {
            "request_id": str(uuid.uuid4()),
            "document_id": document.document_id,
            "signer_id": signer.signer_id,
            "signer_fingerprint": lumina_fp,
            "document_hash": document_hash,  # claims to be correct
            "signature_armor": signature_armor,  # but signed wrong data
            "field_values": {},
            "signed_at": datetime.now(timezone.utc).isoformat(),
        }

        transport = SealSKCommsTransport(store=tmp_store)

        with pytest.raises(ValueError, match="[Ss]ignature verification failed"):
            transport.apply_signing_response(response_payload, verify=True)

    def test_skips_duplicate_signature(self, tmp_store, lumina_keys):
        priv_lumina, pub_lumina = lumina_keys
        engine = SealEngine()
        lumina_fp = engine._extract_fingerprint(priv_lumina)

        document_hash = "hashxyz"
        document, signer = self._setup_document(tmp_store, lumina_fp, document_hash)
        tmp_store.store_public_key(lumina_fp, pub_lumina)

        signature_armor = engine._pgp_sign(
            document_hash.encode("utf-8"), priv_lumina, PASSPHRASE
        )
        response_payload = {
            "request_id": str(uuid.uuid4()),
            "document_id": document.document_id,
            "signer_id": signer.signer_id,
            "signer_fingerprint": lumina_fp,
            "document_hash": document_hash,
            "signature_armor": signature_armor,
            "field_values": {},
            "signed_at": datetime.now(timezone.utc).isoformat(),
        }

        transport = SealSKCommsTransport(store=tmp_store)
        # Apply once
        transport.apply_signing_response(response_payload, verify=True)
        # Apply again — should not raise, should be a no-op
        doc_again = transport.apply_signing_response(response_payload, verify=False)
        # Only one signature record (not duplicated)
        assert len(doc_again.signatures) == 1


# ---------------------------------------------------------------------------
# Full round-trip: Peer A sends → Peer B receives → Peer B signs → Peer A applies
# ---------------------------------------------------------------------------

class TestFullP2PRoundTrip:
    def test_end_to_end_signing(self, tmp_store, chef_keys, lumina_keys):
        """
        Full round-trip:
          Peer A (chef) sends a signing request.
          Peer B (lumina) receives it, signs, sends response.
          Peer A applies the response.
          Document status becomes COMPLETED.
        """
        priv_chef, pub_chef = chef_keys
        priv_lumina, pub_lumina = lumina_keys
        engine = SealEngine()
        chef_fp = engine._extract_fingerprint(priv_chef)
        lumina_fp = engine._extract_fingerprint(priv_lumina)

        document_hash = engine.hash_bytes(b"contract-content")
        signer = Signer(name="Lumina", fingerprint=lumina_fp)
        document = Document(
            title="Partnership Agreement",
            pdf_hash=document_hash,
            status=DocumentStatus.PENDING,
            signers=[signer],
        )
        tmp_store.save_document(document)
        tmp_store.store_public_key(lumina_fp, pub_lumina)

        # ── Peer A sends signing request ──────────────────────────────
        sent_messages: list[dict] = []

        def mock_send(recipient, message, *, message_type, urgency, thread_id=None, in_reply_to=None):
            sent_messages.append({
                "recipient": recipient,
                "message": message,
                "message_type": message_type,
            })
            report = MagicMock()
            report.delivered = True
            report.transport = "syncthing"
            report.error = None
            return report

        skcomms_peer_a = MagicMock()
        skcomms_peer_a.send.side_effect = mock_send

        transport_a = SealSKCommsTransport(store=tmp_store, identity_fingerprint=chef_fp)
        result = transport_a.send_signing_request(
            skcomms=skcomms_peer_a,
            document_id=document.document_id,
            signer_fingerprint=lumina_fp,
            sender_fingerprint=chef_fp,
        )
        assert result["delivered"] is True
        request_id = result["request_id"]

        # ── Peer B receives and signs ──────────────────────────────────
        # The message was "delivered" — simulate it appearing in Peer B's inbox
        from skcomms.models import MessageType

        sent_envelope = MagicMock()
        sent_envelope.envelope_id = str(uuid.uuid4())
        sent_envelope.sender = chef_fp
        sent_envelope.payload.content_type = MessageType.SIGNING_REQUEST
        sent_envelope.payload.content = sent_messages[0]["message"]

        response_messages: list[dict] = []

        def mock_send_b(recipient, message, *, message_type, urgency, thread_id=None, in_reply_to=None):
            response_messages.append({
                "recipient": recipient,
                "message": message,
                "message_type": message_type,
            })
            report = MagicMock()
            report.delivered = True
            report.transport = "syncthing"
            report.error = None
            return report

        skcomms_peer_b = MagicMock()
        skcomms_peer_b.receive.return_value = [sent_envelope]
        skcomms_peer_b.send.side_effect = mock_send_b

        transport_b = SealSKCommsTransport(store=tmp_store, identity_fingerprint=lumina_fp)
        requests = transport_b.receive_signing_requests(skcomms_peer_b)

        assert len(requests) == 1
        req = requests[0]
        assert req["request_id"] == request_id
        assert req["document_hash"] == document_hash

        sign_result = transport_b.respond_to_signing_request(
            skcomms=skcomms_peer_b,
            request_payload=req,
            private_key_armor=priv_lumina,
            passphrase=PASSPHRASE,
        )
        assert sign_result["signed"] is True
        assert sign_result["delivered"] is True

        # ── Peer A receives and applies the response ───────────────────
        response_env = MagicMock()
        response_env.envelope_id = str(uuid.uuid4())
        response_env.sender = lumina_fp
        response_env.payload.content_type = MessageType.SIGNING_RESPONSE
        response_env.payload.content = response_messages[0]["message"]

        skcomms_peer_a.receive.return_value = [response_env]

        results = transport_a.poll_and_apply_responses(skcomms_peer_a, verify=True)
        assert len(results) == 1
        assert results[0]["applied"] is True
        assert results[0]["document_status"] == "completed"

        # Final document state
        final_doc = tmp_store.load_document(document.document_id)
        assert final_doc.status == DocumentStatus.COMPLETED
        assert len(final_doc.signatures) == 1
        assert final_doc.signatures[0].fingerprint == lumina_fp
