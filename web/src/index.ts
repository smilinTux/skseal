/**
 * @skseal/web — Client-side document signing with OpenPGP.js.
 *
 * Keys never leave the browser. This library provides:
 *
 * - **crypto** — PGP key generation, signing, and verification via OpenPGP.js
 * - **keystore** — IndexedDB-backed key storage (passphrase-protected at rest)
 * - **client** — HTTP client for the SKSeal REST API
 * - **SigningSession** — High-level orchestrator tying it all together
 *
 * Quick start:
 *
 * ```ts
 * import { SigningSession } from "@skseal/web";
 *
 * const session = new SigningSession({ apiUrl: "https://seal.example.com" });
 *
 * // Generate a key (stored in browser IndexedDB, public key sent to server)
 * const key = await session.generateKey("Chef", "chef@example.com", "my-passphrase");
 *
 * // Sign a document (PDF downloaded, signed locally, signature sent to server)
 * const { document } = await session.sign("doc-id", key.fingerprint, "my-passphrase");
 *
 * // Verify locally (no server round-trip for crypto)
 * const results = await session.verifyLocally("doc-id");
 * ```
 */

// Core crypto
export {
  generateKeyPair,
  importPrivateKey,
  importPublicKey,
  hashBytes,
  signDocument,
  signBytes,
  verifySignature,
  extractFingerprint,
} from "./crypto.js";

// Key storage
export { KeyStore } from "./keystore.js";

// API client
export { SealClient } from "./client.js";
export type { SealClientOptions } from "./client.js";

// High-level session
export { SigningSession } from "./signing-session.js";
export type { SigningSessionOptions } from "./signing-session.js";

// Types
export type {
  FieldType,
  DocumentStatus,
  SignerRole,
  SignerStatus,
  FieldPlacement,
  FieldPreferences,
  FieldValidation,
  DocumentField,
  Signer,
  SignatureRecord,
  AuditEntry,
  Document,
  Template,
  KeyPair,
  StoredKey,
  SigningResult,
  VerificationResult,
  ClientSignRequest,
} from "./types.js";
