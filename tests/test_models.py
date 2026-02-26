"""Tests for SKSeal Pydantic models."""

from skseal.models import (
    Document,
    DocumentField,
    DocumentStatus,
    FieldPlacement,
    FieldPreferences,
    FieldType,
    FieldValidation,
    Signer,
    SignerRole,
    SignerStatus,
    SignatureRecord,
    Template,
    TemplateDocument,
    TemplateSettings,
    TemplateSubmitter,
)


class TestFieldPlacement:
    """Field placement uses normalized 0-1 coordinates."""

    def test_defaults(self):
        p = FieldPlacement()
        assert p.page == 1
        assert 0.0 <= p.x <= 1.0
        assert 0.0 <= p.y <= 1.0
        assert p.w == 0.2
        assert p.h == 0.025

    def test_custom_placement(self):
        p = FieldPlacement(page=3, x=0.5, y=0.7, w=0.3, h=0.05)
        assert p.page == 3
        assert p.x == 0.5


class TestDocumentField:
    """Fields follow DocuSeal JSON structure."""

    def test_default_field(self):
        f = DocumentField(name="Buyer Name")
        assert f.name == "Buyer Name"
        assert f.field_type == FieldType.TEXT
        assert f.required is True
        assert f.uuid  # auto-generated

    def test_signature_field(self):
        f = DocumentField(
            name="Buyer Signature",
            field_type=FieldType.SIGNATURE,
            role="Buyer",
            areas=[FieldPlacement(page=2, x=0.1, y=0.8, w=0.4, h=0.06)],
        )
        assert f.field_type == FieldType.SIGNATURE
        assert f.role == "Buyer"
        assert len(f.areas) == 1
        assert f.areas[0].page == 2

    def test_field_with_validation(self):
        f = DocumentField(
            name="Phone",
            field_type=FieldType.PHONE,
            validation=FieldValidation(
                pattern=r"^\+?[0-9]{10,15}$",
                message="Enter a valid phone number",
            ),
        )
        assert f.validation is not None
        assert f.validation.pattern is not None

    def test_json_roundtrip(self):
        f = DocumentField(
            name="Test",
            field_type=FieldType.DATE,
            preferences=FieldPreferences(font_size=14, align="center"),
        )
        data = f.model_dump(by_alias=True)
        restored = DocumentField.model_validate(data)
        assert restored.name == "Test"
        assert restored.preferences.font_size == 14


class TestSigner:
    """Signer identity is PGP fingerprint, not email."""

    def test_create_signer(self):
        s = Signer(name="Chef", fingerprint="A" * 40)
        assert s.status == SignerStatus.PENDING
        assert s.signed_at is None

    def test_signer_with_role(self):
        s = Signer(
            name="Lumina",
            fingerprint="B" * 40,
            role=SignerRole.WITNESS,
            email="lumina@smilintux.org",
        )
        assert s.role == SignerRole.WITNESS


class TestDocument:
    """Document lifecycle and properties."""

    def test_empty_document(self):
        doc = Document(title="Test NDA")
        assert doc.status == DocumentStatus.DRAFT
        assert doc.is_complete is True  # no signers = vacuously complete
        assert doc.pending_signers == []
        assert doc.next_signer is None

    def test_document_with_signers(self):
        doc = Document(
            title="Operating Agreement",
            signers=[
                Signer(name="Chef", fingerprint="A" * 40, order=0),
                Signer(name="Lumina", fingerprint="B" * 40, order=1),
            ],
        )
        assert doc.is_complete is False
        assert len(doc.pending_signers) == 2
        assert doc.next_signer.name == "Chef"

    def test_document_completion(self):
        doc = Document(
            title="Test",
            signers=[
                Signer(
                    name="Chef",
                    fingerprint="A" * 40,
                    status=SignerStatus.SIGNED,
                ),
            ],
        )
        assert doc.is_complete is True


class TestTemplate:
    """Template follows DocuSeal JSON structure."""

    def test_create_template(self):
        t = Template(
            name="Simple NDA",
            documents=[
                TemplateDocument(
                    name="NDA Agreement",
                    fields=[
                        DocumentField(name="Party Name", role="Signer"),
                        DocumentField(
                            name="Signature",
                            field_type=FieldType.SIGNATURE,
                            role="Signer",
                        ),
                    ],
                ),
            ],
            submitters=[
                TemplateSubmitter(role="Signer", order=0),
            ],
        )
        assert t.name == "Simple NDA"
        assert len(t.documents) == 1
        assert len(t.documents[0].fields) == 2
        assert t.settings.expire_after_days == 30

    def test_template_settings(self):
        s = TemplateSettings(
            expire_after_days=60,
            sequential_signing=False,
            allow_decline=False,
        )
        assert s.expire_after_days == 60
        assert s.sequential_signing is False
