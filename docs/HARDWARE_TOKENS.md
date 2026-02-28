# SKSeal Hardware Token Guide

Sign documents with YubiKey, NitroKey, or any PKCS#11-compatible HSM.
Private keys never leave the device — signing happens on the token itself.

## Supported Tokens

| Token | PKCS#11 Module | Notes |
|-------|---------------|-------|
| YubiKey 5 | `libykcs11.so` or OpenSC | OpenPGP applet preferred |
| NitroKey Pro | OpenSC (`opensc-pkcs11.so`) | PKCS#15 compatible |
| NitroKey Start | OpenSC | Budget-friendly option |
| SoftHSM2 | `libsofthsm2.so` | For development/testing only |

## Installation

### 1. Install SKSeal with PKCS#11 support

```bash
pip install skseal[pkcs11]
```

This pulls in **PyKCS11** which bridges Python to PKCS#11 libraries.

### 2. Install the PKCS#11 driver

**Debian / Ubuntu:**
```bash
sudo apt install opensc libykcs11-1 pcscd scdaemon
sudo systemctl enable --now pcscd
```

**Arch / Manjaro:**
```bash
sudo pacman -S opensc ccid pcsc-tools
sudo systemctl enable --now pcscd
```

**macOS:**
```bash
brew install opensc yubico-piv-tool
```

### 3. Verify your token is detected

```bash
# List PKCS#11 tokens
skseal token list

# If auto-detection fails, specify the module:
skseal token list --module /usr/lib/opensc-pkcs11.so
```

Expected output:
```
╭──────────────────────────────────────╮
│         PKCS#11 Tokens               │
├────┬──────────────┬─────────────┬────┤
│ #  │ Label        │ Model       │ Key│
├────┼──────────────┼─────────────┼────┤
│ 0  │ OpenPGP card │ YubiKey 5   │ ✓  │
╰────┴──────────────┴─────────────┴────╯
```

## Signing a Document

### CLI

```bash
# Sign with auto-detected token (prompts for PIN)
skseal token sign contract.pdf --name "Alice Sovereign"

# Specify token by label
skseal token sign contract.pdf \
  --name "Alice Sovereign" \
  --token-label "OpenPGP card" \
  --pin prompt

# Specify a specific key on the token
skseal token sign contract.pdf \
  --name "Alice Sovereign" \
  --key-label "Signing Key" \
  --slot 0
```

### Python API

```python
from skseal.engine import SealEngine
from skseal.pkcs11 import PKCS11Config

engine = SealEngine()

# Create or load a document
doc = engine.create_document(
    title="Service Agreement",
    pdf_path="contract.pdf",
    signers=[{"name": "Alice", "email": "alice@example.com"}],
)

# Sign with hardware token
config = PKCS11Config(
    token_label="OpenPGP card",
    pin="123456",  # or prompt at runtime
)
doc = engine.sign_document_pkcs11(
    document=doc,
    signer_id=doc.signers[0].signer_id,
    config=config,
    pdf_path="contract.pdf",
)
```

## PKCS#11 Module Paths

SKSeal searches these paths automatically:

| OS | Path |
|----|------|
| Linux (x86_64) | `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` |
| Linux (generic) | `/usr/lib/opensc-pkcs11.so` |
| YubiKey (Linux) | `/usr/lib/libykcs11.so` |
| SoftHSM (Linux) | `/usr/lib/softhsm/libsofthsm2.so` |
| macOS (Homebrew) | `/opt/homebrew/lib/opensc-pkcs11.so` |
| macOS (system) | `/usr/local/lib/opensc-pkcs11.so` |

Override with `--module` flag or `PKCS11Config(module_path=...)`.

## Troubleshooting

### Token not detected

1. Check `pcscd` is running: `sudo systemctl status pcscd`
2. List USB devices: `lsusb | grep -i yubi` or `pcsc_scan`
3. Try the module path explicitly: `skseal token list --module /path/to/module.so`

### Wrong PIN / PIN locked

- YubiKey default PIN: `123456`, Admin PIN: `12345678`
- NitroKey default PIN: `123456`, Admin PIN: `12345678`
- After 3 wrong PINs the token locks. Use `openpgp-tool --reset` to factory reset.

### PyKCS11 import error

```bash
pip install PyKCS11
# On some systems you also need:
sudo apt install swig libpcsclite-dev
```

### No signing key on token

Generate a key pair on the token first:
```bash
# YubiKey: use ykman
ykman openpgp keys generate sig

# NitroKey: use openpgp-tool
openpgp-tool --gen-key 1
```

## Signature Format

Hardware token signatures use this format in the audit trail:

```
-----BEGIN PKCS11 SIGNATURE-----
Token: OpenPGP card
Algorithm: sha256

[base64-encoded raw signature]
-----END PKCS11 SIGNATURE-----
```

This is stored alongside PGP signatures in `SignatureRecord.signature_armor`
and verified the same way — the document hash is compared against the
signature using the token's public key.

## Security Notes

- Private keys are generated on and never leave the hardware token
- PIN entry is required for each signing operation
- YubiKey supports physical touch confirmation (recommended)
- All signing events are recorded in the immutable audit trail
- Hash algorithm defaults to SHA-256; SHA-384 and SHA-512 also supported
