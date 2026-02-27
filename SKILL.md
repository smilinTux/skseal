# SKSeal Skill
## SKILL.md - Sovereign Document Signing System

**Name:** skseal
**Version:** 0.1.0
**Author:** smilinTux Team
**Category:** Document Signing & Verification
**License:** MIT

---

## Description

Sovereign document signing system built on PGP cryptography. SKSeal lets any agent or user sign PDF documents with their PGP key, verify signatures, manage document templates, and maintain a tamper-evident audit trail — all without third-party signing services.

**Signing Backend:** PGP (via pgpy)
**Document Format:** PDF (via pypdf)
**API:** FastAPI server for headless and multi-agent use
**Audit:** Append-only audit trail per document

---

## Installation

### Python (recommended)

```bash
pip install skseal
```

### From Source

```bash
git clone https://github.com/smilinTux/skseal.git
cd skseal
pip install -e .
```

### SKSkills Integration

```bash
skskills install skseal
skskills enable skseal
```

---

## Quick Start

### Sign a Document

```bash
skseal sign contract.pdf
```

### Verify Signatures

```bash
skseal verify contract.pdf
```

### Start the API Server

```bash
skseal serve
```

### View the Audit Trail

```bash
skseal audit contract.pdf
```

---

## CLI Commands

| Command | Flags | Description |
|---------|-------|-------------|
| `skseal sign <file>` | | Sign a PDF document with your PGP key |
| `skseal verify <file>` | | Verify all signatures on a document |
| `skseal list` | | List all documents tracked by SKSeal |
| `skseal audit <file>` | | Show the full audit trail for a document |
| `skseal templates` | | List all available signing templates |
| `skseal serve` | `--host`, `--port`, `--reload` | Start the SKSeal FastAPI server |

### Global Options

| Option | Description |
|--------|-------------|
| `--data-dir PATH` | Override the default data directory (default: `~/.skseal/`) |

---

## Configuration

### Default Paths

```
~/.skseal/
  documents/          # Signed and tracked PDF files
  templates/          # Reusable signing templates
  audit/              # Per-document audit trail logs
  keys/               # Cached or imported PGP key references
```

### Environment Variables

```bash
export SKSEAL_DATA_DIR=~/.skseal        # Override data directory
export SKSEAL_PGP_KEY_ID=ABCD1234      # Default signing key fingerprint
export SKSEAL_SERVER_HOST=127.0.0.1    # API server bind host
export SKSEAL_SERVER_PORT=8200         # API server bind port
```

---

## Architecture

```
~/.skseal/
  documents/
    contract-abc123.pdf          # Original or signed PDF
    contract-abc123.sig.json     # Detached signature metadata
  templates/
    nda-template.json            # Field layout definitions
  audit/
    contract-abc123.audit.jsonl  # Append-only audit log
```

**Stack:**
- **pgpy** — PGP signing and verification
- **pypdf** — PDF parsing and manipulation
- **FastAPI + uvicorn** — Headless REST API for agent and browser use
- **pydantic** — Schema validation for signatures and templates
- **click + rich** — CLI interface with styled terminal output

**Signing flow:**
1. Load PGP key from keyring or `--data-dir`
2. Hash the PDF content
3. Create a detached PGP signature
4. Append a record to the document audit trail
5. Optionally embed signature metadata into PDF metadata fields

---

## API Server

When running `skseal serve`, the following REST endpoints are available:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/sign` | Sign a document (multipart upload) |
| `POST` | `/verify` | Verify signatures on a document |
| `GET` | `/documents` | List all tracked documents |
| `GET` | `/audit/{doc_id}` | Get audit trail for a document |
| `GET` | `/templates` | List templates |

---

## Support

- GitHub: https://github.com/smilinTux/skseal
- Discord: https://discord.gg/5767MCWbFR
- Email: support@smilintux.org

---

## Philosophy

> *"Your signature is your sovereign identity. No third party should hold the pen."*

SKSeal gives documents the same weight as a hand-signed page, verified by cryptography rather than trust in a vendor. Every signature is traceable. Every document has a history.

**Part of the Penguin Kingdom.**
