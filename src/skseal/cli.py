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
from .store import DocumentStore

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


if __name__ == "__main__":
    main()
