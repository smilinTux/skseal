"""SKSeal CLI — sovereign document signing from the command line.

Usage:
    skseal sign <pdf> --key <private.asc> --name "Chef"
    skseal verify <document-id>
    skseal list [--status pending]
    skseal templates
    skseal create-from-template <template-id> --title "My NDA"
    skseal serve [--port 8400]
"""

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .engine import SealEngine
from .models import (
    AuditAction,
    AuditEntry,
    Document,
    DocumentStatus,
    Signer,
    SignerStatus,
)
from .models_timestamp import TimestampConfig, TimestampStatus
from .store import DocumentStore
from .timestamp import DEFAULT_TSA_URL, load_tsr_file, timestamp_document, verify_timestamp

console = Console()
engine = SealEngine()


@click.group()
@click.option(
    "--data-dir",
    type=click.Path(),
    default=None,
    help="SKSeal data directory (default: ~/.skseal)",
)
@click.pass_context
def main(ctx: click.Context, data_dir: Optional[str]) -> None:
    """SKSeal — Sovereign Document Signing.

    PGP-backed, legally binding, no middleman.
    """
    ctx.ensure_object(dict)
    base = Path(data_dir) if data_dir else None
    ctx.obj["store"] = DocumentStore(base)


# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------

@main.command()
@click.argument("pdf", type=click.Path(exists=True))
@click.option("--key", required=True, type=click.Path(exists=True), help="Path to PGP private key (armored)")
@click.option("--passphrase", prompt=True, hide_input=True, help="Key passphrase")
@click.option("--name", required=True, help="Signer display name")
@click.option("--title", default=None, help="Document title")
@click.pass_context
def sign(
    ctx: click.Context,
    pdf: str,
    key: str,
    passphrase: str,
    name: str,
    title: Optional[str],
) -> None:
    """Sign a PDF document with your PGP key."""
    store: DocumentStore = ctx.obj["store"]
    pdf_path = Path(pdf)
    key_armor = Path(key).read_text(encoding="utf-8")

    doc_title = title or pdf_path.stem
    pdf_data = pdf_path.read_bytes()
    pdf_hash = engine.hash_bytes(pdf_data)

    fingerprint = engine._extract_fingerprint(key_armor)

    signer = Signer(name=name, fingerprint=fingerprint)
    doc = Document(
        title=doc_title,
        pdf_path=str(pdf_path),
        pdf_hash=pdf_hash,
        signers=[signer],
        status=DocumentStatus.PENDING,
    )
    doc.audit_trail.append(
        AuditEntry(
            document_id=doc.document_id,
            action=AuditAction.CREATED,
            actor_fingerprint=fingerprint,
            actor_name=name,
            details=f"Created and signing: {doc_title}",
        )
    )

    doc = engine.sign_document(
        document=doc,
        signer_id=signer.signer_id,
        private_key_armor=key_armor,
        passphrase=passphrase,
        pdf_data=pdf_data,
    )

    store.save_document(doc, pdf_data=pdf_data)
    for entry in doc.audit_trail:
        store.append_audit(entry)

    console.print(
        Panel(
            f"[bold green]Document signed![/]\n\n"
            f"  Document: {doc.title}\n"
            f"  ID:       {doc.document_id[:16]}...\n"
            f"  Hash:     {pdf_hash[:16]}...\n"
            f"  Signer:   {name}\n"
            f"  Key:      {fingerprint[:16]}...\n"
            f"  Status:   {doc.status.value}",
            title="SKSeal",
            border_style="green",
        )
    )


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

@main.command()
@click.argument("document_id")
@click.option("--pubkey", type=click.Path(exists=True), multiple=True, help="Public key file(s)")
@click.pass_context
def verify(ctx: click.Context, document_id: str, pubkey: tuple[str, ...]) -> None:
    """Verify all signatures on a document."""
    store: DocumentStore = ctx.obj["store"]

    try:
        doc = store.load_document(document_id)
    except FileNotFoundError:
        console.print(f"[red]Document not found: {document_id}[/]")
        sys.exit(1)

    public_keys: dict[str, str] = {}
    for pk_path in pubkey:
        armor = Path(pk_path).read_text(encoding="utf-8")
        fp = engine._extract_fingerprint(armor)
        public_keys[fp] = armor

    for record in doc.signatures:
        if record.fingerprint not in public_keys:
            cached = store.get_public_key(record.fingerprint)
            if cached:
                public_keys[record.fingerprint] = cached

    pdf_data = store.get_document_pdf(document_id)
    results = engine.verify_document(doc, public_keys, pdf_data=pdf_data)

    table = Table(title=f"Verification: {doc.title}")
    table.add_column("Signer", style="cyan")
    table.add_column("Fingerprint", style="dim")
    table.add_column("Status", justify="center")

    signer_map = {s.signer_id: s for s in doc.signers}
    all_valid = True
    for sid, valid in results.items():
        signer = signer_map.get(sid)
        name = signer.name if signer else "Unknown"
        fp = next(
            (r.fingerprint[:16] for r in doc.signatures if r.signer_id == sid),
            "?",
        )
        status = "[bold green]VALID[/]" if valid else "[bold red]INVALID[/]"
        if not valid:
            all_valid = False
        table.add_row(name, f"{fp}...", status)

    console.print(table)
    if not all_valid:
        sys.exit(1)


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------

@main.command("list")
@click.option("--status", default=None, help="Filter by status")
@click.pass_context
def list_docs(ctx: click.Context, status: Optional[str]) -> None:
    """List all documents."""
    store: DocumentStore = ctx.obj["store"]
    status_filter = DocumentStatus(status) if status else None
    docs = store.list_documents(status=status_filter)

    if not docs:
        console.print("[dim]No documents found.[/]")
        return

    table = Table(title="SKSeal Documents")
    table.add_column("ID", style="dim", max_width=12)
    table.add_column("Title", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Signers", justify="right")
    table.add_column("Created")

    for doc in docs:
        signed = sum(1 for s in doc.signers if s.status == SignerStatus.SIGNED)
        total = len(doc.signers)
        status_color = {
            DocumentStatus.DRAFT: "dim",
            DocumentStatus.PENDING: "yellow",
            DocumentStatus.PARTIALLY_SIGNED: "blue",
            DocumentStatus.COMPLETED: "green",
            DocumentStatus.VOIDED: "red",
            DocumentStatus.EXPIRED: "red",
        }.get(doc.status, "white")

        table.add_row(
            doc.document_id[:12],
            doc.title,
            f"[{status_color}]{doc.status.value}[/]",
            f"{signed}/{total}",
            doc.created_at.strftime("%Y-%m-%d %H:%M"),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

@main.command()
@click.pass_context
def templates(ctx: click.Context) -> None:
    """List all templates."""
    store: DocumentStore = ctx.obj["store"]
    tpls = store.list_templates()

    if not tpls:
        console.print("[dim]No templates found.[/]")
        return

    table = Table(title="SKSeal Templates")
    table.add_column("ID", style="dim", max_width=12)
    table.add_column("Name", style="cyan")
    table.add_column("Roles", justify="right")
    table.add_column("Fields", justify="right")
    table.add_column("Created")

    for t in tpls:
        total_fields = sum(len(d.fields) for d in t.documents)
        roles = ", ".join(s.role for s in t.submitters) or "—"
        table.add_row(
            t.template_id[:12],
            t.name,
            roles,
            str(total_fields),
            t.created_at.strftime("%Y-%m-%d %H:%M"),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

@main.command()
@click.argument("document_id")
@click.pass_context
def audit(ctx: click.Context, document_id: str) -> None:
    """Show the audit trail for a document."""
    store: DocumentStore = ctx.obj["store"]
    entries = store.get_audit_trail(document_id)

    if not entries:
        console.print("[dim]No audit entries found.[/]")
        return

    table = Table(title="Audit Trail")
    table.add_column("Time", style="dim")
    table.add_column("Action", style="cyan")
    table.add_column("Actor")
    table.add_column("Details")

    for e in entries:
        table.add_row(
            e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            e.action.value,
            e.actor_name or e.actor_fingerprint or "—",
            e.details,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Serve
# ---------------------------------------------------------------------------

@main.command()
@click.option("--host", default="127.0.0.1", help="Bind address")
@click.option("--port", default=8400, help="Port")
@click.pass_context
def serve(ctx: click.Context, host: str, port: int) -> None:
    """Start the SKSeal API server."""
    import uvicorn

    console.print(
        f"[bold]SKSeal API[/] listening on [cyan]http://{host}:{port}[/]"
    )
    console.print("[dim]Sovereign document signing — no middleman.[/]\n")
    uvicorn.run("skseal.api:app", host=host, port=port, log_level="info")


# ---------------------------------------------------------------------------
# Timestamp
# ---------------------------------------------------------------------------


@main.group()
def timestamp() -> None:
    """RFC 3161 timestamp commands for non-repudiation proof."""


@timestamp.command("stamp")
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--tsa",
    "tsa_url",
    default=None,
    help=f"TSA endpoint URL (default: {DEFAULT_TSA_URL})",
)
@click.option(
    "--algorithm",
    default="sha256",
    type=click.Choice(["sha256", "sha384", "sha512"]),
    help="Hash algorithm (default: sha256)",
)
@click.option(
    "--no-save",
    is_flag=True,
    default=False,
    help="Do not save .tsr token file alongside document",
)
@click.pass_context
def timestamp_stamp(
    ctx: click.Context,
    file: str,
    tsa_url: Optional[str],
    algorithm: str,
    no_save: bool,
) -> None:
    """Timestamp a document via an RFC 3161 TSA.

    Hashes the file, submits the hash to a Time Stamping Authority, and
    saves the token as <file>.tsr. Provides non-repudiation proof that the
    file existed in its current form at the certified time.
    """
    from .models_timestamp import HashAlgorithm

    config = TimestampConfig(
        tsa_url=tsa_url or DEFAULT_TSA_URL,
        hash_algorithm=HashAlgorithm(algorithm),
    )

    with console.status(f"[bold]Submitting timestamp request to {config.tsa_url}...[/]"):
        try:
            result = timestamp_document(
                file_path=file,
                config=config,
                save_token=not no_save,
            )
        except FileNotFoundError as exc:
            console.print(f"[red]File not found: {exc}[/]")
            sys.exit(1)
        except Exception as exc:
            console.print(f"[red]Timestamp failed: {exc}[/]")
            sys.exit(1)

    if result.error:
        console.print(
            Panel(
                f"[bold red]Timestamp failed[/]\n\n{result.error}",
                title="SKSeal Timestamp",
                border_style="red",
            )
        )
        sys.exit(1)

    ts_display = (
        result.response.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        if result.response and result.response.timestamp
        else "unknown"
    )
    status_color = "green" if result.is_valid else "yellow"
    status_text = result.verification_status.value.upper()

    console.print(
        Panel(
            f"[bold {status_color}]Timestamp {status_text}[/]\n\n"
            f"  File:       {result.file_path}\n"
            f"  Hash:       {result.file_hash[:32]}...\n"
            f"  Algorithm:  {result.hash_algorithm.value}\n"
            f"  TSA:        {result.tsa_url}\n"
            f"  Certified:  {ts_display}\n"
            f"  Serial:     {result.response.serial_number if result.response else 'N/A'}\n"
            f"  Token:      {result.tsr_path or '(not saved)'}",
            title="SKSeal Timestamp",
            border_style=status_color,
        )
    )


@timestamp.command("verify")
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--token",
    "tsr_file",
    default=None,
    type=click.Path(),
    help="Path to .tsr token file (default: <file>.tsr)",
)
@click.option(
    "--tsa",
    "tsa_url",
    default=DEFAULT_TSA_URL,
    help="TSA URL to embed in metadata (informational)",
)
@click.pass_context
def timestamp_verify(
    ctx: click.Context,
    file: str,
    tsr_file: Optional[str],
    tsa_url: str,
) -> None:
    """Verify a timestamp token against a document.

    Checks that the .tsr token covers the given file and the message imprint
    matches the document's current content.
    """
    import hashlib
    from pathlib import Path

    file_path = Path(file).resolve()
    tsr_path = tsr_file or str(file_path) + ".tsr"

    if not Path(tsr_path).exists():
        console.print(f"[red]Token file not found: {tsr_path}[/]")
        console.print(
            "[dim]Run [bold]skseal timestamp stamp <file>[/] first to create a token.[/]"
        )
        sys.exit(1)

    try:
        response = load_tsr_file(tsr_path, tsa_url=tsa_url)
    except Exception as exc:
        console.print(f"[red]Failed to load token: {exc}[/]")
        sys.exit(1)

    file_bytes = file_path.read_bytes()

    try:
        is_valid = verify_timestamp(response, file_bytes)
    except Exception as exc:
        console.print(f"[red]Verification error: {exc}[/]")
        sys.exit(1)

    status_color = "green" if is_valid else "red"
    status_text = "VALID" if is_valid else "INVALID"

    ts_display = (
        response.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        if response.timestamp
        else "unknown"
    )

    console.print(
        Panel(
            f"[bold {status_color}]Timestamp {status_text}[/]\n\n"
            f"  File:      {file_path}\n"
            f"  Token:     {tsr_path}\n"
            f"  TSA:       {response.tsa_url}\n"
            f"  Certified: {ts_display}\n"
            f"  Serial:    {response.serial_number or 'N/A'}",
            title="SKSeal Timestamp Verify",
            border_style=status_color,
        )
    )

    if not is_valid:
        sys.exit(1)


@timestamp.command("info")
@click.argument("tsr_file", type=click.Path(exists=True))
@click.option(
    "--tsa",
    "tsa_url",
    default=DEFAULT_TSA_URL,
    help="TSA URL to embed in metadata (informational)",
)
def timestamp_info(tsr_file: str, tsa_url: str) -> None:
    """Show details of a .tsr timestamp token file.

    Parses and displays the token metadata without verifying against a
    specific document.
    """
    try:
        response = load_tsr_file(tsr_file, tsa_url=tsa_url)
    except Exception as exc:
        console.print(f"[red]Failed to load token: {exc}[/]")
        sys.exit(1)

    ts_display = (
        response.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        if response.timestamp
        else "unknown"
    )

    table = Table(title=f"Timestamp Token: {tsr_file}")
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("Status", str(response.status))
    table.add_row("Status String", response.status_string or "—")
    table.add_row("TSA URL", response.tsa_url)
    table.add_row("Certified Time", ts_display)
    table.add_row("Serial Number", str(response.serial_number or "—"))
    table.add_row("Hash Algorithm", response.hash_algorithm.value)
    table.add_row(
        "Message Imprint",
        (response.message_imprint[:32] + "...") if response.message_imprint else "—",
    )
    table.add_row("Policy OID", response.policy_id or "—")
    table.add_row(
        "Accuracy",
        f"{response.accuracy_seconds}s" if response.accuracy_seconds else "—",
    )
    table.add_row("Nonce", str(response.nonce) if response.nonce else "—")
    table.add_row("TSA Name", response.tsa_name or "—")
    table.add_row(
        "Token Size",
        f"{len(response.token_der)} bytes" if response.token_der else "—",
    )
    table.add_row("Granted", "[green]Yes[/]" if response.is_granted else "[red]No[/]")

    console.print(table)


# ---------------------------------------------------------------------------
# Token (PKCS#11 hardware token)
# ---------------------------------------------------------------------------


@main.group()
def token() -> None:
    """PKCS#11 hardware token commands (YubiKey, NitroKey, HSM)."""


@token.command("list")
@click.option(
    "--module",
    "module_path",
    default=None,
    type=click.Path(),
    help="Path to PKCS#11 module (.so/.dylib). Auto-detected if omitted.",
)
def token_list(module_path: Optional[str]) -> None:
    """List available hardware tokens and their signing keys."""
    from .pkcs11 import find_pkcs11_module, list_tokens

    if module_path is None:
        module_path = find_pkcs11_module()
        if module_path is None:
            console.print(
                "[red]No PKCS#11 module found.[/]\n"
                "[dim]Install OpenSC or specify --module path.[/]"
            )
            sys.exit(1)
        console.print(f"[dim]Using module: {module_path}[/]\n")

    try:
        tokens = list_tokens(module_path)
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/]")
        sys.exit(1)

    if not tokens:
        console.print("[dim]No tokens found.[/]")
        return

    table = Table(title="PKCS#11 Hardware Tokens")
    table.add_column("Slot", style="dim", justify="right")
    table.add_column("Label", style="cyan")
    table.add_column("Manufacturer")
    table.add_column("Model")
    table.add_column("Serial", style="dim")
    table.add_column("Signing Key", justify="center")

    for t in tokens:
        key_status = (
            f"[green]Yes[/] ({t.key_label or t.key_id or '?'})"
            if t.has_private_key
            else "[dim]No[/]"
        )
        table.add_row(
            str(t.slot_id),
            t.label,
            t.manufacturer,
            t.model,
            t.serial,
            key_status,
        )

    console.print(table)


@token.command("sign")
@click.argument("pdf", type=click.Path(exists=True))
@click.option("--module", "module_path", default=None, type=click.Path(), help="PKCS#11 module path")
@click.option("--pin", prompt=True, hide_input=True, help="Token PIN")
@click.option("--name", required=True, help="Signer display name")
@click.option("--title", default=None, help="Document title")
@click.option("--slot", "slot_id", default=None, type=int, help="Token slot ID")
@click.option("--token-label", default=None, help="Token label to match")
@click.option("--key-id", default=None, help="Key ID on token (hex)")
@click.option("--key-label", default=None, help="Key label on token")
@click.pass_context
def token_sign(
    ctx: click.Context,
    pdf: str,
    module_path: Optional[str],
    pin: str,
    name: str,
    title: Optional[str],
    slot_id: Optional[int],
    token_label: Optional[str],
    key_id: Optional[str],
    key_label: Optional[str],
) -> None:
    """Sign a PDF using a hardware token (YubiKey, NitroKey, HSM).

    The private key never leaves the token. Only the document hash
    is sent to the device for signing.
    """
    from .pkcs11 import PKCS11Config, find_pkcs11_module

    store: DocumentStore = ctx.obj["store"]
    pdf_path = Path(pdf)
    pdf_data = pdf_path.read_bytes()
    pdf_hash = engine.hash_bytes(pdf_data)

    if module_path is None:
        module_path = find_pkcs11_module()
        if module_path is None:
            console.print(
                "[red]No PKCS#11 module found.[/] Specify --module."
            )
            sys.exit(1)

    config = PKCS11Config(
        module_path=module_path,
        token_label=token_label,
        slot_id=slot_id,
        pin=pin,
        key_id=key_id,
        key_label=key_label,
    )

    doc_title = title or pdf_path.stem
    fingerprint = key_id or "PKCS11-TOKEN"

    signer = Signer(name=name, fingerprint=fingerprint)
    doc = Document(
        title=doc_title,
        pdf_path=str(pdf_path),
        pdf_hash=pdf_hash,
        signers=[signer],
        status=DocumentStatus.PENDING,
    )
    doc.audit_trail.append(
        AuditEntry(
            document_id=doc.document_id,
            action=AuditAction.CREATED,
            actor_fingerprint=fingerprint,
            actor_name=name,
            details=f"Created for hardware signing: {doc_title}",
        )
    )

    with console.status("[bold]Signing with hardware token...[/]"):
        try:
            doc = engine.sign_document_pkcs11(
                document=doc,
                signer_id=signer.signer_id,
                config=config,
                pdf_data=pdf_data,
            )
        except RuntimeError as exc:
            console.print(f"[red]Hardware signing failed: {exc}[/]")
            sys.exit(1)

    store.save_document(doc, pdf_data=pdf_data)
    for entry in doc.audit_trail:
        store.append_audit(entry)

    console.print(
        Panel(
            f"[bold green]Document signed with hardware token![/]\n\n"
            f"  Document: {doc.title}\n"
            f"  ID:       {doc.document_id[:16]}...\n"
            f"  Hash:     {pdf_hash[:16]}...\n"
            f"  Signer:   {name}\n"
            f"  Token:    {token_label or 'default'}\n"
            f"  Status:   {doc.status.value}",
            title="SKSeal — Hardware Token",
            border_style="green",
        )
    )


@token.command("info")
@click.option("--module", "module_path", default=None, type=click.Path(), help="PKCS#11 module path")
def token_info(module_path: Optional[str]) -> None:
    """Show detailed info about the PKCS#11 environment."""
    from .pkcs11 import DEFAULT_MODULE_PATHS, _has_pkcs11, find_pkcs11_module

    console.print(Panel("[bold]PKCS#11 Environment[/]", border_style="cyan"))

    # PyKCS11 availability
    if _has_pkcs11():
        console.print("  PyKCS11:  [green]installed[/]")
    else:
        console.print("  PyKCS11:  [red]not installed[/]")
        console.print("  [dim]Install with: pip install PyKCS11[/]")
        return

    # Module detection
    detected = find_pkcs11_module()
    console.print(f"  Module:   {detected or '[dim]none found[/]'}")

    # Available module paths
    console.print("\n  [bold]Module paths searched:[/]")
    for p in DEFAULT_MODULE_PATHS:
        exists = Path(p).exists()
        marker = "[green]found[/]" if exists else "[dim]—[/]"
        console.print(f"    {p}  {marker}")


if __name__ == "__main__":
    main()
