"""Tests for the SKSeal signing engine."""

import pytest

from skseal.engine import SealEngine
from skseal.models import (
    Document,
    DocumentStatus,
    Signer,
    SignerStatus,
)

from .conftest import PASSPHRASE


engine = SealEngine()


class TestHashing:
    """SHA-256 hashing of documents."""

    def test_hash_bytes(self, sample_pdf):
        h = engine.hash_bytes(sample_pdf)
        assert len(h) == 64
        assert h == engine.hash_bytes(sample_pdf)  # deterministic

    def test_hash_file(self, sample_pdf, tmp_path):
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(sample_pdf)
        h = engine.hash_file(pdf_path)
        assert h == engine.hash_bytes(sample_pdf)

    def test_different_content_different_hash(self, sample_pdf):
        h1 = engine.hash_bytes(sample_pdf)
        h2 = engine.hash_bytes(sample_pdf + b"modified")
        assert h1 != h2


class TestSigning:
    """PGP document signing."""

    def test_sign_document(self, chef_keys, sample_pdf):
        priv, pub = chef_keys
        signer = Signer(name="Chef", fingerprint="placeholder")
        doc = Document(
            title="Test Agreement",
            signers=[signer],
            status=DocumentStatus.PENDING,
            pdf_hash=engine.hash_bytes(sample_pdf),
        )

        doc = engine.sign_document(
            document=doc,
            signer_id=signer.signer_id,
            private_key_armor=priv,
            passphrase=PASSPHRASE,
            pdf_data=sample_pdf,
        )

        assert doc.status == DocumentStatus.COMPLETED
        assert doc.completed_at is not None
        assert len(doc.signatures) == 1
        assert doc.signers[0].status == SignerStatus.SIGNED
        assert doc.signers[0].signed_at is not None
        assert len(doc.audit_trail) >= 1

    def test_multi_signer(self, chef_keys, lumina_keys, sample_pdf):
        chef_priv, _ = chef_keys
        lumina_priv, _ = lumina_keys

        signer1 = Signer(name="Chef", fingerprint="placeholder", order=0)
        signer2 = Signer(name="Lumina", fingerprint="placeholder", order=1)
        doc = Document(
            title="Joint Agreement",
            signers=[signer1, signer2],
            status=DocumentStatus.PENDING,
            pdf_hash=engine.hash_bytes(sample_pdf),
        )

        doc = engine.sign_document(
            document=doc,
            signer_id=signer1.signer_id,
            private_key_armor=chef_priv,
            passphrase=PASSPHRASE,
            pdf_data=sample_pdf,
        )
        assert doc.status == DocumentStatus.PARTIALLY_SIGNED

        doc = engine.sign_document(
            document=doc,
            signer_id=signer2.signer_id,
            private_key_armor=lumina_priv,
            passphrase=PASSPHRASE,
            pdf_data=sample_pdf,
        )
        assert doc.status == DocumentStatus.COMPLETED
        assert len(doc.signatures) == 2

    def test_cannot_sign_voided(self, chef_keys, sample_pdf):
        priv, _ = chef_keys
        signer = Signer(name="Chef", fingerprint="placeholder")
        doc = Document(
            title="Voided",
            signers=[signer],
            status=DocumentStatus.VOIDED,
        )
        with pytest.raises(ValueError, match="voided"):
            engine.sign_document(
                document=doc,
                signer_id=signer.signer_id,
                private_key_armor=priv,
                passphrase=PASSPHRASE,
                pdf_data=sample_pdf,
            )

    def test_cannot_double_sign(self, chef_keys, sample_pdf):
        priv, _ = chef_keys
        signer = Signer(
            name="Chef",
            fingerprint="placeholder",
            status=SignerStatus.SIGNED,
        )
        doc = Document(
            title="Already Signed",
            signers=[signer],
            status=DocumentStatus.PENDING,
        )
        with pytest.raises(ValueError, match="already signed"):
            engine.sign_document(
                document=doc,
                signer_id=signer.signer_id,
                private_key_armor=priv,
                passphrase=PASSPHRASE,
                pdf_data=sample_pdf,
            )


class TestVerification:
    """PGP signature verification."""

    def test_verify_valid_signature(self, chef_keys, sample_pdf):
        priv, pub = chef_keys
        signer = Signer(name="Chef", fingerprint="placeholder")
        doc = Document(
            title="Test",
            signers=[signer],
            status=DocumentStatus.PENDING,
            pdf_hash=engine.hash_bytes(sample_pdf),
        )

        doc = engine.sign_document(
            document=doc,
            signer_id=signer.signer_id,
            private_key_armor=priv,
            passphrase=PASSPHRASE,
            pdf_data=sample_pdf,
        )

        record = doc.signatures[0]
        assert engine.verify_signature(record, pub, pdf_data=sample_pdf) is True

    def test_detect_tampered_document(self, chef_keys, sample_pdf):
        priv, pub = chef_keys
        signer = Signer(name="Chef", fingerprint="placeholder")
        doc = Document(
            title="Test",
            signers=[signer],
            status=DocumentStatus.PENDING,
        )

        doc = engine.sign_document(
            document=doc,
            signer_id=signer.signer_id,
            private_key_armor=priv,
            passphrase=PASSPHRASE,
            pdf_data=sample_pdf,
        )

        tampered = sample_pdf + b"TAMPERED"
        record = doc.signatures[0]
        assert engine.verify_signature(record, pub, pdf_data=tampered) is False

    def test_verify_wrong_key(self, chef_keys, lumina_keys, sample_pdf):
        chef_priv, _ = chef_keys
        _, lumina_pub = lumina_keys

        signer = Signer(name="Chef", fingerprint="placeholder")
        doc = Document(
            title="Test",
            signers=[signer],
            status=DocumentStatus.PENDING,
        )

        doc = engine.sign_document(
            document=doc,
            signer_id=signer.signer_id,
            private_key_armor=chef_priv,
            passphrase=PASSPHRASE,
            pdf_data=sample_pdf,
        )

        record = doc.signatures[0]
        assert engine.verify_signature(record, lumina_pub, pdf_data=sample_pdf) is False

    def test_verify_all_signatures(self, chef_keys, lumina_keys, sample_pdf):
        chef_priv, chef_pub = chef_keys
        lumina_priv, lumina_pub = lumina_keys

        s1 = Signer(name="Chef", fingerprint="placeholder", order=0)
        s2 = Signer(name="Lumina", fingerprint="placeholder", order=1)
        doc = Document(
            title="Joint",
            signers=[s1, s2],
            status=DocumentStatus.PENDING,
        )

        doc = engine.sign_document(
            document=doc,
            signer_id=s1.signer_id,
            private_key_armor=chef_priv,
            passphrase=PASSPHRASE,
            pdf_data=sample_pdf,
        )
        doc = engine.sign_document(
            document=doc,
            signer_id=s2.signer_id,
            private_key_armor=lumina_priv,
            passphrase=PASSPHRASE,
            pdf_data=sample_pdf,
        )

        fp1 = doc.signatures[0].fingerprint
        fp2 = doc.signatures[1].fingerprint
        keys = {fp1: chef_pub, fp2: lumina_pub}

        results = engine.verify_document(doc, keys, pdf_data=sample_pdf)
        assert all(results.values())


class TestSeal:
    """Tamper-evident document seal."""

    def test_seal_completed_document(self, chef_keys, sample_pdf):
        priv, pub = chef_keys
        signer = Signer(name="Chef", fingerprint="placeholder")
        doc = Document(
            title="Test",
            signers=[signer],
            status=DocumentStatus.PENDING,
        )

        doc = engine.sign_document(
            document=doc,
            signer_id=signer.signer_id,
            private_key_armor=priv,
            passphrase=PASSPHRASE,
            pdf_data=sample_pdf,
        )

        seal = engine.seal_document(doc, priv, PASSPHRASE)
        assert "PGP MESSAGE" in seal

        assert engine.verify_seal(doc, seal, pub) is True

    def test_cannot_seal_incomplete(self, chef_keys):
        priv, _ = chef_keys
        doc = Document(
            title="Incomplete",
            signers=[Signer(name="Chef", fingerprint="A" * 40)],
            status=DocumentStatus.PENDING,
        )
        with pytest.raises(ValueError, match="incomplete"):
            engine.seal_document(doc, priv, PASSPHRASE)
