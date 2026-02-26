"""Tests for the SKSeal document store."""

import pytest

from skseal.models import (
    AuditAction,
    AuditEntry,
    Document,
    DocumentField,
    DocumentStatus,
    FieldType,
    Signer,
    Template,
    TemplateDocument,
    TemplateSubmitter,
)
from skseal.store import DocumentStore


class TestTemplateStore:
    """Template CRUD operations."""

    def test_save_and_load_template(self, tmp_store):
        t = Template(
            name="Test NDA",
            documents=[
                TemplateDocument(
                    name="NDA",
                    fields=[DocumentField(name="Name")],
                )
            ],
            submitters=[TemplateSubmitter(role="Signer")],
        )
        tmp_store.save_template(t)
        loaded = tmp_store.load_template(t.template_id)
        assert loaded.name == "Test NDA"
        assert len(loaded.documents) == 1

    def test_list_templates(self, tmp_store):
        for i in range(3):
            tmp_store.save_template(Template(name=f"Template {i}"))
        assert len(tmp_store.list_templates()) == 3

    def test_delete_template(self, tmp_store):
        t = Template(name="Delete Me")
        tmp_store.save_template(t)
        assert tmp_store.delete_template(t.template_id) is True
        assert tmp_store.delete_template(t.template_id) is False

    def test_load_missing_template(self, tmp_store):
        with pytest.raises(FileNotFoundError):
            tmp_store.load_template("nonexistent")


class TestDocumentStore:
    """Document CRUD with PDF storage."""

    def test_save_and_load_document(self, tmp_store, sample_pdf):
        doc = Document(title="My Agreement")
        tmp_store.save_document(doc, pdf_data=sample_pdf)

        loaded = tmp_store.load_document(doc.document_id)
        assert loaded.title == "My Agreement"

    def test_pdf_storage(self, tmp_store, sample_pdf):
        doc = Document(title="PDF Test")
        tmp_store.save_document(doc, pdf_data=sample_pdf)

        retrieved = tmp_store.get_document_pdf(doc.document_id)
        assert retrieved == sample_pdf

    def test_list_with_status_filter(self, tmp_store):
        tmp_store.save_document(
            Document(title="Draft", status=DocumentStatus.DRAFT)
        )
        tmp_store.save_document(
            Document(title="Complete", status=DocumentStatus.COMPLETED)
        )

        drafts = tmp_store.list_documents(status=DocumentStatus.DRAFT)
        assert len(drafts) == 1
        assert drafts[0].title == "Draft"

    def test_delete_document(self, tmp_store, sample_pdf):
        doc = Document(title="Delete Me")
        tmp_store.save_document(doc, pdf_data=sample_pdf)
        assert tmp_store.delete_document(doc.document_id) is True
        assert tmp_store.get_document_pdf(doc.document_id) is None

    def test_load_missing_document(self, tmp_store):
        with pytest.raises(FileNotFoundError):
            tmp_store.load_document("nonexistent")


class TestAuditLog:
    """Append-only JSONL audit trail."""

    def test_append_and_read(self, tmp_store):
        doc_id = "test-doc-123"
        tmp_store.append_audit(
            AuditEntry(
                document_id=doc_id,
                action=AuditAction.CREATED,
                actor_name="Chef",
                details="Document created",
            )
        )
        tmp_store.append_audit(
            AuditEntry(
                document_id=doc_id,
                action=AuditAction.SIGNED,
                actor_name="Chef",
                details="Signed by Chef",
            )
        )

        trail = tmp_store.get_audit_trail(doc_id)
        assert len(trail) == 2
        assert trail[0].action == AuditAction.CREATED
        assert trail[1].action == AuditAction.SIGNED

    def test_empty_audit_trail(self, tmp_store):
        assert tmp_store.get_audit_trail("nonexistent") == []


class TestKeyCache:
    """Public key caching for verification."""

    def test_store_and_retrieve_key(self, tmp_store):
        fp = "A" * 40
        armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----"
        tmp_store.store_public_key(fp, armor)

        retrieved = tmp_store.get_public_key(fp)
        assert retrieved == armor

    def test_list_keys(self, tmp_store):
        tmp_store.store_public_key("A" * 40, "key-a")
        tmp_store.store_public_key("B" * 40, "key-b")
        keys = tmp_store.list_public_keys()
        assert len(keys) == 2

    def test_missing_key(self, tmp_store):
        assert tmp_store.get_public_key("nonexistent") is None
