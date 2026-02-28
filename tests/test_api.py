"""Tests for SKSeal FastAPI endpoints (sign, verify, store, retrieve)."""

import pytest
from fastapi.testclient import TestClient

import skseal.api as api_module
from skseal.engine import SealEngine
from skseal.store import DocumentStore

from .conftest import PASSPHRASE

engine = SealEngine()


@pytest.fixture
def client(monkeypatch, tmp_path):
    """TestClient backed by a fresh isolated DocumentStore."""
    store = DocumentStore(base_dir=tmp_path)
    monkeypatch.setattr(api_module, "_store", store)
    return TestClient(api_module.app)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class TestHealth:
    def test_health_ok(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["service"] == "skseal"
        assert "version" in data


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------


class TestTemplates:
    def test_create_template(self, client):
        r = client.post("/api/templates", json={"name": "NDA Template"})
        assert r.status_code == 201
        data = r.json()
        assert data["name"] == "NDA Template"
        assert "template_id" in data

    def test_list_templates_empty(self, client):
        r = client.get("/api/templates")
        assert r.status_code == 200
        assert r.json() == []

    def test_list_templates(self, client):
        client.post("/api/templates", json={"name": "T1"})
        client.post("/api/templates", json={"name": "T2"})
        r = client.get("/api/templates")
        assert r.status_code == 200
        assert len(r.json()) == 2

    def test_get_template(self, client):
        resp = client.post("/api/templates", json={"name": "MyTemplate"})
        tid = resp.json()["template_id"]
        r = client.get(f"/api/templates/{tid}")
        assert r.status_code == 200
        assert r.json()["name"] == "MyTemplate"

    def test_get_template_not_found(self, client):
        r = client.get("/api/templates/nonexistent-id")
        assert r.status_code == 404

    def test_delete_template(self, client):
        resp = client.post("/api/templates", json={"name": "ToDelete"})
        tid = resp.json()["template_id"]
        r = client.delete(f"/api/templates/{tid}")
        assert r.status_code == 204
        r2 = client.get(f"/api/templates/{tid}")
        assert r2.status_code == 404

    def test_delete_template_not_found(self, client):
        r = client.delete("/api/templates/nonexistent")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------


class TestDocuments:
    def test_create_document(self, client):
        r = client.post(
            "/api/documents", json={"title": "Test Agreement", "description": "A test"}
        )
        assert r.status_code == 201
        data = r.json()
        assert data["title"] == "Test Agreement"
        assert "document_id" in data
        assert data["status"] == "draft"

    def test_create_document_sets_audit_entry(self, client):
        r = client.post("/api/documents", json={"title": "Audited"})
        doc_id = r.json()["document_id"]
        audit = client.get(f"/api/documents/{doc_id}/audit").json()
        assert len(audit) >= 1
        assert audit[0]["action"] == "created"

    def test_list_documents_empty(self, client):
        r = client.get("/api/documents")
        assert r.status_code == 200
        assert r.json() == []

    def test_list_documents(self, client):
        client.post("/api/documents", json={"title": "Doc1"})
        client.post("/api/documents", json={"title": "Doc2"})
        r = client.get("/api/documents")
        assert r.status_code == 200
        assert len(r.json()) == 2

    def test_get_document(self, client):
        resp = client.post("/api/documents", json={"title": "MyDoc"})
        doc_id = resp.json()["document_id"]
        r = client.get(f"/api/documents/{doc_id}")
        assert r.status_code == 200
        assert r.json()["title"] == "MyDoc"

    def test_get_document_not_found(self, client):
        r = client.get("/api/documents/nonexistent")
        assert r.status_code == 404

    def test_delete_document(self, client):
        resp = client.post("/api/documents", json={"title": "ToDelete"})
        doc_id = resp.json()["document_id"]
        r = client.delete(f"/api/documents/{doc_id}")
        assert r.status_code == 204
        r2 = client.get(f"/api/documents/{doc_id}")
        assert r2.status_code == 404

    def test_delete_document_not_found(self, client):
        r = client.delete("/api/documents/nonexistent")
        assert r.status_code == 404

    def test_create_document_from_missing_template(self, client):
        r = client.post(
            "/api/documents",
            json={"title": "From Template", "template_id": "nonexistent-template"},
        )
        assert r.status_code == 404

    def test_upload_pdf(self, client, sample_pdf):
        resp = client.post("/api/documents", json={"title": "PDF Doc"})
        doc_id = resp.json()["document_id"]
        r = client.post(
            f"/api/documents/{doc_id}/upload",
            files={"file": ("test.pdf", sample_pdf, "application/pdf")},
        )
        assert r.status_code == 200
        assert r.json()["pdf_hash"] is not None

    def test_upload_pdf_document_not_found(self, client, sample_pdf):
        r = client.post(
            "/api/documents/nonexistent/upload",
            files={"file": ("test.pdf", sample_pdf, "application/pdf")},
        )
        assert r.status_code == 404

    def test_download_pdf(self, client, sample_pdf):
        resp = client.post("/api/documents", json={"title": "PDF Doc"})
        doc_id = resp.json()["document_id"]
        client.post(
            f"/api/documents/{doc_id}/upload",
            files={"file": ("test.pdf", sample_pdf, "application/pdf")},
        )
        r = client.get(f"/api/documents/{doc_id}/pdf")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/pdf"
        assert r.content == sample_pdf

    def test_download_pdf_no_attachment(self, client):
        resp = client.post("/api/documents", json={"title": "No PDF"})
        doc_id = resp.json()["document_id"]
        r = client.get(f"/api/documents/{doc_id}/pdf")
        assert r.status_code == 404

    def test_get_audit_trail(self, client):
        resp = client.post("/api/documents", json={"title": "Audited Doc"})
        doc_id = resp.json()["document_id"]
        r = client.get(f"/api/documents/{doc_id}/audit")
        assert r.status_code == 200
        entries = r.json()
        assert isinstance(entries, list)
        assert len(entries) >= 1

    def test_list_documents_filter_by_status(self, client):
        client.post("/api/documents", json={"title": "Draft Doc"})
        r = client.get("/api/documents", params={"status": "draft"})
        assert r.status_code == 200
        docs = r.json()
        assert all(d["status"] == "draft" for d in docs)


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


class TestSigning:
    def _create_doc_with_signer(self, client):
        resp = client.post(
            "/api/documents",
            json={
                "title": "Sign Test",
                "signers": [{"name": "Chef", "fingerprint": "placeholder"}],
            },
        )
        assert resp.status_code == 201
        doc = resp.json()
        return doc["document_id"], doc["signers"][0]["signer_id"]

    def test_sign_document(self, client, chef_keys, sample_pdf):
        priv, pub = chef_keys
        doc_id, signer_id = self._create_doc_with_signer(client)
        client.post(
            f"/api/documents/{doc_id}/upload",
            files={"file": ("test.pdf", sample_pdf, "application/pdf")},
        )
        r = client.post(
            f"/api/documents/{doc_id}/sign",
            json={
                "signer_id": signer_id,
                "private_key_armor": priv,
                "passphrase": PASSPHRASE,
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] in ("completed", "partially_signed")
        assert len(data["signatures"]) == 1

    def test_sign_document_not_found(self, client, chef_keys):
        priv, _ = chef_keys
        r = client.post(
            "/api/documents/nonexistent/sign",
            json={"signer_id": "x", "private_key_armor": priv, "passphrase": PASSPHRASE},
        )
        assert r.status_code == 404

    def test_sign_document_bad_signer_id(self, client, chef_keys, sample_pdf):
        priv, _ = chef_keys
        doc_id, _ = self._create_doc_with_signer(client)
        client.post(
            f"/api/documents/{doc_id}/upload",
            files={"file": ("test.pdf", sample_pdf, "application/pdf")},
        )
        r = client.post(
            f"/api/documents/{doc_id}/sign",
            json={
                "signer_id": "bad-signer-id",
                "private_key_armor": priv,
                "passphrase": PASSPHRASE,
            },
        )
        assert r.status_code == 400

    def test_sign_document_wrong_passphrase(self, client, chef_keys, sample_pdf):
        priv, _ = chef_keys
        doc_id, signer_id = self._create_doc_with_signer(client)
        client.post(
            f"/api/documents/{doc_id}/upload",
            files={"file": ("test.pdf", sample_pdf, "application/pdf")},
        )
        r = client.post(
            f"/api/documents/{doc_id}/sign",
            json={
                "signer_id": signer_id,
                "private_key_armor": priv,
                "passphrase": "wrong-passphrase",
            },
        )
        assert r.status_code == 500

    def test_multi_signer_partial_then_complete(self, client, chef_keys, lumina_keys, sample_pdf):
        chef_priv, _ = chef_keys
        lumina_priv, _ = lumina_keys

        resp = client.post(
            "/api/documents",
            json={
                "title": "Multi-Signer",
                "signers": [
                    {"name": "Chef", "fingerprint": "placeholder-chef"},
                    {"name": "Lumina", "fingerprint": "placeholder-lumina"},
                ],
            },
        )
        doc = resp.json()
        doc_id = doc["document_id"]
        chef_sid = doc["signers"][0]["signer_id"]
        lumina_sid = doc["signers"][1]["signer_id"]

        client.post(
            f"/api/documents/{doc_id}/upload",
            files={"file": ("test.pdf", sample_pdf, "application/pdf")},
        )

        # First signature → partially_signed
        r1 = client.post(
            f"/api/documents/{doc_id}/sign",
            json={"signer_id": chef_sid, "private_key_armor": chef_priv, "passphrase": PASSPHRASE},
        )
        assert r1.status_code == 200
        assert r1.json()["status"] == "partially_signed"

        # Second signature → completed
        r2 = client.post(
            f"/api/documents/{doc_id}/sign",
            json={"signer_id": lumina_sid, "private_key_armor": lumina_priv, "passphrase": PASSPHRASE},
        )
        assert r2.status_code == 200
        assert r2.json()["status"] == "completed"


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


class TestVerify:
    def test_verify_signatures(self, client, chef_keys, sample_pdf):
        priv, pub = chef_keys
        resp = client.post(
            "/api/documents",
            json={
                "title": "Verify Test",
                "signers": [{"name": "Chef", "fingerprint": "placeholder"}],
            },
        )
        doc = resp.json()
        doc_id = doc["document_id"]
        signer_id = doc["signers"][0]["signer_id"]

        client.post(
            f"/api/documents/{doc_id}/upload",
            files={"file": ("test.pdf", sample_pdf, "application/pdf")},
        )
        client.post(
            f"/api/documents/{doc_id}/sign",
            json={"signer_id": signer_id, "private_key_armor": priv, "passphrase": PASSPHRASE},
        )

        signed_doc = client.get(f"/api/documents/{doc_id}").json()
        fingerprint = signed_doc["signatures"][0]["fingerprint"]

        r = client.post(
            f"/api/documents/{doc_id}/verify",
            json={"public_keys": {fingerprint: pub}},
        )
        assert r.status_code == 200
        results = r.json()
        assert len(results) == 1
        assert results[0]["valid"] is True

    def test_verify_document_not_found(self, client):
        r = client.post("/api/documents/nonexistent/verify", json={"public_keys": {}})
        assert r.status_code == 404

    def test_verify_no_signatures_returns_empty(self, client):
        resp = client.post("/api/documents", json={"title": "Unsigned"})
        doc_id = resp.json()["document_id"]
        r = client.post(f"/api/documents/{doc_id}/verify", json={"public_keys": {}})
        assert r.status_code == 200
        assert r.json() == []


# ---------------------------------------------------------------------------
# Seal
# ---------------------------------------------------------------------------


class TestSeal:
    def test_seal_incomplete_document_fails(self, client, chef_keys):
        priv, _ = chef_keys
        resp = client.post(
            "/api/documents",
            json={
                "title": "Seal Fail",
                "signers": [{"name": "Chef", "fingerprint": "placeholder"}],
            },
        )
        doc_id = resp.json()["document_id"]
        r = client.post(
            f"/api/documents/{doc_id}/seal",
            json={"sealing_key_armor": priv, "passphrase": PASSPHRASE},
        )
        assert r.status_code == 400

    def test_seal_completed_document(self, client, chef_keys, sample_pdf):
        priv, _ = chef_keys
        resp = client.post(
            "/api/documents",
            json={
                "title": "Seal Test",
                "signers": [{"name": "Chef", "fingerprint": "placeholder"}],
            },
        )
        doc = resp.json()
        doc_id = doc["document_id"]
        signer_id = doc["signers"][0]["signer_id"]

        client.post(
            f"/api/documents/{doc_id}/upload",
            files={"file": ("test.pdf", sample_pdf, "application/pdf")},
        )
        client.post(
            f"/api/documents/{doc_id}/sign",
            json={"signer_id": signer_id, "private_key_armor": priv, "passphrase": PASSPHRASE},
        )

        r = client.post(
            f"/api/documents/{doc_id}/seal",
            json={"sealing_key_armor": priv, "passphrase": PASSPHRASE},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "sealed"
        assert "seal" in data
        assert data["document_id"] == doc_id

    def test_seal_document_not_found(self, client, chef_keys):
        priv, _ = chef_keys
        r = client.post(
            "/api/documents/nonexistent/seal",
            json={"sealing_key_armor": priv, "passphrase": PASSPHRASE},
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------


class TestKeys:
    def test_store_and_list_keys(self, client, chef_keys):
        _, pub = chef_keys
        fp = engine._extract_fingerprint(pub)

        r = client.post("/api/keys", params={"fingerprint": fp, "armor": pub})
        assert r.status_code == 201
        assert r.json()["stored"] is True
        assert r.json()["fingerprint"] == fp

        r2 = client.get("/api/keys")
        assert r2.status_code == 200
        assert fp in r2.json()

    def test_register_public_key(self, client, chef_keys):
        _, pub = chef_keys
        fp = engine._extract_fingerprint(pub)

        r = client.post("/api/keys/register", json={"fingerprint": fp, "armor": pub})
        assert r.status_code == 201
        data = r.json()
        assert data["fingerprint"] == fp
        assert data["stored"] is True

    def test_list_keys_empty(self, client):
        r = client.get("/api/keys")
        assert r.status_code == 200
        assert r.json() == []


# ---------------------------------------------------------------------------
# Client-side signing (sign-client)
# ---------------------------------------------------------------------------


class TestClientSigning:
    def test_sign_client_no_cached_key_returns_400(self, client, chef_keys, sample_pdf):
        priv, _ = chef_keys
        fp = engine._extract_fingerprint(priv)
        doc_hash = engine.hash_bytes(sample_pdf)
        sig = engine._pgp_sign(doc_hash.encode(), priv, PASSPHRASE)

        resp = client.post(
            "/api/documents",
            json={
                "title": "Client Sign Test",
                "signers": [{"name": "Chef", "fingerprint": fp}],
            },
        )
        doc = resp.json()
        doc_id = doc["document_id"]
        signer_id = doc["signers"][0]["signer_id"]

        r = client.post(
            f"/api/documents/{doc_id}/sign-client",
            json={
                "signer_id": signer_id,
                "signature_armor": sig,
                "document_hash": doc_hash,
                "fingerprint": fp,
            },
        )
        # No cached public key → 400
        assert r.status_code == 400

    def test_sign_client_with_registered_key(self, client, chef_keys, sample_pdf):
        priv, pub = chef_keys
        fp = engine._extract_fingerprint(priv)
        doc_hash = engine.hash_bytes(sample_pdf)
        sig = engine._pgp_sign(doc_hash.encode(), priv, PASSPHRASE)

        # Register the public key first
        client.post("/api/keys/register", json={"fingerprint": fp, "armor": pub})

        resp = client.post(
            "/api/documents",
            json={
                "title": "Client Sign Happy Path",
                "signers": [{"name": "Chef", "fingerprint": fp}],
            },
        )
        doc = resp.json()
        doc_id = doc["document_id"]
        signer_id = doc["signers"][0]["signer_id"]

        r = client.post(
            f"/api/documents/{doc_id}/sign-client",
            json={
                "signer_id": signer_id,
                "signature_armor": sig,
                "document_hash": doc_hash,
                "fingerprint": fp,
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] in ("completed", "partially_signed")

    def test_sign_client_signer_not_found(self, client, chef_keys, sample_pdf):
        priv, _ = chef_keys
        fp = engine._extract_fingerprint(priv)
        doc_hash = engine.hash_bytes(sample_pdf)
        sig = engine._pgp_sign(doc_hash.encode(), priv, PASSPHRASE)

        resp = client.post("/api/documents", json={"title": "Client Sign Bad Signer"})
        doc_id = resp.json()["document_id"]

        r = client.post(
            f"/api/documents/{doc_id}/sign-client",
            json={
                "signer_id": "nonexistent-signer",
                "signature_armor": sig,
                "document_hash": doc_hash,
                "fingerprint": fp,
            },
        )
        assert r.status_code == 400

    def test_sign_client_document_not_found(self, client, chef_keys, sample_pdf):
        priv, _ = chef_keys
        fp = engine._extract_fingerprint(priv)
        doc_hash = engine.hash_bytes(sample_pdf)
        sig = engine._pgp_sign(doc_hash.encode(), priv, PASSPHRASE)

        r = client.post(
            "/api/documents/nonexistent/sign-client",
            json={
                "signer_id": "x",
                "signature_armor": sig,
                "document_hash": doc_hash,
                "fingerprint": fp,
            },
        )
        assert r.status_code == 404
