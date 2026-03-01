# SKSeal

![PyPI](https://img.shields.io/pypi/v/skseal) ![License](https://img.shields.io/badge/license-MIT-blue) ![Python](https://img.shields.io/badge/python-3.10%2B-blue)

Sovereign document sealing with OpenPGP. Sign PDFs with your PGP key, verify signatures client-side, and maintain a tamper-evident audit trail — no middleman, no cloud, no trust required.

## Features

- **PGP signing** — sign PDFs with an armored private key or a PKCS#11 hardware token (YubiKey, NitroKey, HSM)
- **Client-side verification** — verify all signatures locally; public keys never leave your machine
- **RFC 3161 timestamps** — certify documents with a Time Stamping Authority for non-repudiation proof
- **Audit trail** — every action (create, sign, verify, void) is appended to an immutable log
- **REST API** — FastAPI server on port 8400 for integration with other services
- **MCP server** — expose signing tools to AI agents via the Model Context Protocol

## Install

```bash
pip install skseal

# Optional extras
pip install "skseal[timestamp]"   # RFC 3161 TSA support
pip install "skseal[pkcs11]"      # PKCS#11 hardware token support
pip install "skseal[all]"         # Everything
```

## Quick Usage

```bash
# Sign a PDF
skseal sign contract.pdf --key private.asc --name "Alice"

# Verify all signatures on a document
skseal verify <document-id> --pubkey alice.pub.asc

# List documents
skseal list
skseal list --status pending

# Show audit trail
skseal audit <document-id>

# Timestamp a file via RFC 3161 TSA
skseal timestamp stamp contract.pdf
skseal timestamp verify contract.pdf

# Sign using a hardware token (YubiKey, NitroKey)
skseal token list
skseal token sign contract.pdf --name "Alice" --pin <PIN>

# Start the REST API server
skseal serve --port 8400
```

### Python API

```python
from skseal.engine import SealEngine
from skseal.models import Document, Signer, DocumentStatus

engine = SealEngine()
pdf_data = open("contract.pdf", "rb").read()
pdf_hash = engine.hash_bytes(pdf_data)

signer = Signer(name="Alice", fingerprint="DEADBEEF...")
doc = Document(title="NDA", pdf_path="contract.pdf", pdf_hash=pdf_hash, signers=[signer])

doc = engine.sign_document(
    document=doc,
    signer_id=signer.signer_id,
    private_key_armor=open("private.asc").read(),
    passphrase="hunter2",
    pdf_data=pdf_data,
)
print(doc.status)  # DocumentStatus.COMPLETED
```

## License

MIT — see [LICENSE](LICENSE).
