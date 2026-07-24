# Mission

skseal exists to make document signing sovereign: sign PDFs with your own PGP key, verify them offline forever, and keep a tamper-evident audit trail, with no DocuSign, no cloud, no account, and no trust required.

It replaces hosted e-signature platforms with a model where identity is a PGP fingerprint, not an email, and keys never leave the signer's device. The engine only ever touches hashes and signatures; the legally binding artifact lives on your filesystem (Syncthing- and git-friendly), not someone else's database.

## Scope

- Hash a document, collect each signer's detached PGP signature over that hash, and produce a SignatureRecord per signer.
- A tamper-evident seal (PGP signature over the whole package) once all signers are done, plus an optional RFC 3161 timestamp for non-repudiation.
- An append-only audit trail (JSONL on disk) and offline verification by anyone holding the signer's public key.

skseal is the document-signing capability of the SKWorld sovereign agent ecosystem.

## Non-goals

- skseal is not a hosted service and needs no server, account, or network to sign or verify.
- It does not hold or escrow private keys; signing happens locally on the signer's device.
- It is not a general identity or crypto home; it consumes PGP identities rather than issuing them.
