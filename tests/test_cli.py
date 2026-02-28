"""Tests for SKSeal CLI commands (sign, verify, list, templates, audit)."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from skseal.cli import main
from skseal.engine import SealEngine
from skseal.models import Document, DocumentStatus, Signer, Template
from skseal.store import DocumentStore

from .conftest import PASSPHRASE

engine = SealEngine()


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def data_dir(tmp_path):
    return str(tmp_path)


@pytest.fixture
def key_file(tmp_path, chef_keys):
    priv, _ = chef_keys
    path = tmp_path / "chef.asc"
    path.write_text(priv, encoding="utf-8")
    return str(path)


@pytest.fixture
def pdf_file(tmp_path, sample_pdf):
    path = tmp_path / "test.pdf"
    path.write_bytes(sample_pdf)
    return str(path)


# ---------------------------------------------------------------------------
# list command
# ---------------------------------------------------------------------------


class TestListCommand:
    def test_list_empty(self, runner, data_dir):
        result = runner.invoke(main, ["--data-dir", data_dir, "list"])
        assert result.exit_code == 0

    def test_list_with_documents(self, runner, data_dir, sample_pdf):
        store = DocumentStore(base_dir=Path(data_dir))
        doc = Document(
            title="Test Agreement",
            signers=[Signer(name="Chef", fingerprint="ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234")],
            status=DocumentStatus.PENDING,
            pdf_hash=engine.hash_bytes(sample_pdf),
        )
        store.save_document(doc)

        result = runner.invoke(main, ["--data-dir", data_dir, "list"])
        assert result.exit_code == 0

    def test_list_with_status_filter(self, runner, data_dir, sample_pdf):
        store = DocumentStore(base_dir=Path(data_dir))
        doc = Document(
            title="Draft One",
            status=DocumentStatus.DRAFT,
            pdf_hash=engine.hash_bytes(sample_pdf),
        )
        store.save_document(doc)

        result = runner.invoke(main, ["--data-dir", data_dir, "list", "--status", "draft"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# templates command
# ---------------------------------------------------------------------------


class TestTemplatesCommand:
    def test_templates_empty(self, runner, data_dir):
        result = runner.invoke(main, ["--data-dir", data_dir, "templates"])
        assert result.exit_code == 0

    def test_templates_with_data(self, runner, data_dir):
        store = DocumentStore(base_dir=Path(data_dir))
        store.save_template(Template(name="NDA Template"))

        result = runner.invoke(main, ["--data-dir", data_dir, "templates"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# sign command
# ---------------------------------------------------------------------------


class TestSignCommand:
    def test_sign_exits_zero(self, runner, data_dir, pdf_file, key_file):
        result = runner.invoke(
            main,
            [
                "--data-dir", data_dir,
                "sign", pdf_file,
                "--key", key_file,
                "--passphrase", PASSPHRASE,
                "--name", "Chef",
            ],
        )
        assert result.exit_code == 0

    def test_sign_creates_document_in_store(self, runner, data_dir, pdf_file, key_file):
        runner.invoke(
            main,
            [
                "--data-dir", data_dir,
                "sign", pdf_file,
                "--key", key_file,
                "--passphrase", PASSPHRASE,
                "--name", "Chef",
                "--title", "My Agreement",
            ],
        )
        store = DocumentStore(base_dir=Path(data_dir))
        docs = store.list_documents()
        assert len(docs) == 1
        assert docs[0].title == "My Agreement"

    def test_sign_document_is_completed(self, runner, data_dir, pdf_file, key_file):
        runner.invoke(
            main,
            [
                "--data-dir", data_dir,
                "sign", pdf_file,
                "--key", key_file,
                "--passphrase", PASSPHRASE,
                "--name", "Chef",
            ],
        )
        store = DocumentStore(base_dir=Path(data_dir))
        docs = store.list_documents()
        assert len(docs) == 1
        # Single signer → should complete
        assert docs[0].status == DocumentStatus.COMPLETED

    def test_sign_creates_signature_record(self, runner, data_dir, pdf_file, key_file):
        runner.invoke(
            main,
            [
                "--data-dir", data_dir,
                "sign", pdf_file,
                "--key", key_file,
                "--passphrase", PASSPHRASE,
                "--name", "Chef",
            ],
        )
        store = DocumentStore(base_dir=Path(data_dir))
        docs = store.list_documents()
        assert len(docs[0].signatures) == 1
        assert docs[0].signatures[0].signature_armor != ""

    def test_sign_wrong_passphrase_fails(self, runner, data_dir, pdf_file, key_file):
        result = runner.invoke(
            main,
            [
                "--data-dir", data_dir,
                "sign", pdf_file,
                "--key", key_file,
                "--passphrase", "wrong-passphrase",
                "--name", "Chef",
            ],
        )
        # Should fail with non-zero exit
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# verify command
# ---------------------------------------------------------------------------


class TestVerifyCommand:
    def _sign_doc(self, runner, data_dir, pdf_file, key_file):
        runner.invoke(
            main,
            [
                "--data-dir", data_dir,
                "sign", pdf_file,
                "--key", key_file,
                "--passphrase", PASSPHRASE,
                "--name", "Chef",
            ],
        )
        store = DocumentStore(base_dir=Path(data_dir))
        docs = store.list_documents()
        assert len(docs) == 1
        return docs[0].document_id

    def test_verify_valid_signature(
        self, runner, tmp_path, data_dir, pdf_file, key_file, chef_keys
    ):
        _, pub = chef_keys
        pub_file = str(tmp_path / "chef.pub.asc")
        Path(pub_file).write_text(pub, encoding="utf-8")

        doc_id = self._sign_doc(runner, data_dir, pdf_file, key_file)

        result = runner.invoke(
            main,
            [
                "--data-dir", data_dir,
                "verify", doc_id,
                "--pubkey", pub_file,
            ],
        )
        assert result.exit_code == 0

    def test_verify_document_not_found(self, runner, data_dir):
        result = runner.invoke(
            main,
            ["--data-dir", data_dir, "verify", "nonexistent-doc-id"],
        )
        assert result.exit_code == 1

    def test_verify_uses_cached_key(self, runner, data_dir, pdf_file, key_file, chef_keys):
        _, pub = chef_keys
        doc_id = self._sign_doc(runner, data_dir, pdf_file, key_file)

        # Get fingerprint and store key in cache manually
        fp = engine._extract_fingerprint(pub)
        store = DocumentStore(base_dir=Path(data_dir))
        store.store_public_key(fp, pub)

        # Verify without --pubkey (relies on cache)
        result = runner.invoke(
            main,
            ["--data-dir", data_dir, "verify", doc_id],
        )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# audit command
# ---------------------------------------------------------------------------


class TestAuditCommand:
    def test_audit_no_entries(self, runner, data_dir):
        result = runner.invoke(
            main,
            ["--data-dir", data_dir, "audit", "nonexistent-id"],
        )
        assert result.exit_code == 0

    def test_audit_shows_entries_after_sign(self, runner, data_dir, pdf_file, key_file):
        runner.invoke(
            main,
            [
                "--data-dir", data_dir,
                "sign", pdf_file,
                "--key", key_file,
                "--passphrase", PASSPHRASE,
                "--name", "Chef",
            ],
        )
        store = DocumentStore(base_dir=Path(data_dir))
        doc_id = store.list_documents()[0].document_id

        result = runner.invoke(
            main,
            ["--data-dir", data_dir, "audit", doc_id],
        )
        assert result.exit_code == 0
        # Confirm the store has audit entries
        entries = store.get_audit_trail(doc_id)
        assert len(entries) >= 1
