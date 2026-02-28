/**
 * Tests for SKSeal browser crypto module.
 *
 * Covers key generation, hashing, signing, and verification using
 * openpgp.js — same algorithms as the Python engine for cross-platform
 * compatibility.
 */

import { describe, it, expect, beforeAll } from "vitest";
import {
  generateKeyPair,
  importPrivateKey,
  importPublicKey,
  hashBytes,
  signDocument,
  signBytes,
  verifySignature,
  extractFingerprint,
} from "../src/crypto.js";

// ---------------------------------------------------------------------------
// Shared keys — generated once for the whole test suite (expensive)
// ---------------------------------------------------------------------------

let alicePrivateArmor: string;
let alicePublicArmor: string;
let aliceFingerprint: string;

const PASSPHRASE = "test-passphrase-vitest";
const SAMPLE_PDF = new TextEncoder().encode(
  "%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF",
).buffer;

beforeAll(async () => {
  const kp = await generateKeyPair("Alice Test", "alice@test.example", PASSPHRASE);
  alicePrivateArmor = kp.privateKeyArmor;
  alicePublicArmor = kp.publicKeyArmor;
  aliceFingerprint = kp.fingerprint;
}, 30000);

// ---------------------------------------------------------------------------
// hashBytes
// ---------------------------------------------------------------------------

describe("hashBytes", () => {
  it("returns a 64-char hex string (SHA-256)", async () => {
    const hash = await hashBytes(SAMPLE_PDF);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic for the same input", async () => {
    const h1 = await hashBytes(SAMPLE_PDF);
    const h2 = await hashBytes(SAMPLE_PDF);
    expect(h1).toBe(h2);
  });

  it("produces different hashes for different inputs", async () => {
    const h1 = await hashBytes(SAMPLE_PDF);
    const h2 = await hashBytes(new TextEncoder().encode("different content").buffer);
    expect(h1).not.toBe(h2);
  });
});

// ---------------------------------------------------------------------------
// generateKeyPair
// ---------------------------------------------------------------------------

describe("generateKeyPair", () => {
  it("returns a fingerprint, public and private armored keys", async () => {
    const kp = await generateKeyPair("Bob Test", "bob@test.example", "pass-bob");
    expect(kp.fingerprint).toMatch(/^[0-9A-F]{40}$/);
    expect(kp.publicKeyArmor).toContain("BEGIN PGP PUBLIC KEY BLOCK");
    expect(kp.privateKeyArmor).toContain("BEGIN PGP PRIVATE KEY BLOCK");
    expect(kp.name).toBe("Bob Test");
    expect(kp.email).toBe("bob@test.example");
    expect(kp.createdAt).toBeInstanceOf(Date);
  });

  it("different calls produce different fingerprints", async () => {
    const kp1 = await generateKeyPair("User A", "a@test.example", "p1");
    const kp2 = await generateKeyPair("User B", "b@test.example", "p2");
    expect(kp1.fingerprint).not.toBe(kp2.fingerprint);
  });
});

// ---------------------------------------------------------------------------
// importPrivateKey / importPublicKey
// ---------------------------------------------------------------------------

describe("importPrivateKey", () => {
  it("extracts name, email, fingerprint, and public key from armored private key", async () => {
    const meta = await importPrivateKey(alicePrivateArmor);
    expect(meta.fingerprint).toBe(aliceFingerprint);
    expect(meta.name).toBe("Alice Test");
    expect(meta.email).toBe("alice@test.example");
    expect(meta.publicKeyArmor).toContain("BEGIN PGP PUBLIC KEY BLOCK");
  });
});

describe("importPublicKey", () => {
  it("extracts name, email, fingerprint from armored public key", async () => {
    const meta = await importPublicKey(alicePublicArmor);
    expect(meta.fingerprint).toBe(aliceFingerprint);
    expect(meta.name).toBe("Alice Test");
    expect(meta.email).toBe("alice@test.example");
  });
});

// ---------------------------------------------------------------------------
// extractFingerprint
// ---------------------------------------------------------------------------

describe("extractFingerprint", () => {
  it("extracts fingerprint from armored public key", async () => {
    const fp = await extractFingerprint(alicePublicArmor);
    expect(fp).toBe(aliceFingerprint);
  });

  it("extracts fingerprint from armored private key", async () => {
    const fp = await extractFingerprint(alicePrivateArmor);
    expect(fp).toBe(aliceFingerprint);
  });
});

// ---------------------------------------------------------------------------
// signDocument + verifySignature (round-trip)
// ---------------------------------------------------------------------------

describe("signDocument + verifySignature", () => {
  it("signs a document and verifies the signature round-trip", async () => {
    const result = await signDocument(SAMPLE_PDF, alicePrivateArmor, PASSPHRASE);

    expect(result.fingerprint).toBe(aliceFingerprint);
    expect(result.documentHash).toMatch(/^[0-9a-f]{64}$/);
    expect(result.signatureArmor).toContain("BEGIN PGP MESSAGE");
    expect(result.signedAt).toBeInstanceOf(Date);

    const verification = await verifySignature(
      SAMPLE_PDF,
      result.signatureArmor,
      alicePublicArmor,
    );

    expect(verification.valid).toBe(true);
    expect(verification.fingerprint).toBe(aliceFingerprint);
    expect(verification.error).toBeUndefined();
  });

  it("fails verification when document content changes after signing", async () => {
    const result = await signDocument(SAMPLE_PDF, alicePrivateArmor, PASSPHRASE);

    const tampered = new TextEncoder().encode("tampered content").buffer;
    const verification = await verifySignature(
      tampered,
      result.signatureArmor,
      alicePublicArmor,
    );

    expect(verification.valid).toBe(false);
    expect(verification.error).toBeDefined();
  });

  it("verifies against expected hash when provided", async () => {
    const result = await signDocument(SAMPLE_PDF, alicePrivateArmor, PASSPHRASE);

    const ok = await verifySignature(
      null,
      result.signatureArmor,
      alicePublicArmor,
      result.documentHash,
    );
    expect(ok.valid).toBe(true);

    const bad = await verifySignature(
      null,
      result.signatureArmor,
      alicePublicArmor,
      "0".repeat(64), // wrong hash
    );
    expect(bad.valid).toBe(false);
  });

  it("returns error result (not throw) when signature is invalid", async () => {
    const result = await verifySignature(
      SAMPLE_PDF,
      "NOT A VALID PGP MESSAGE",
      alicePublicArmor,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// signBytes
// ---------------------------------------------------------------------------

describe("signBytes", () => {
  it("signs raw bytes and produces armored PGP message", async () => {
    const data = new TextEncoder().encode("hello sovereign world");
    const armor = await signBytes(data, alicePrivateArmor, PASSPHRASE);
    expect(armor).toContain("BEGIN PGP MESSAGE");
  });
});
