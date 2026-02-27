/**
 * SKSeal client-side cryptography — OpenPGP.js wrapper.
 *
 * All PGP operations happen in the browser. Private keys are decrypted
 * only in memory for the duration of a signing operation, then discarded.
 * Keys NEVER leave the client — only signatures are sent to the server.
 */

import * as openpgp from "openpgp";
import type { KeyPair, SigningResult, VerificationResult } from "./types.js";

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/**
 * Generate a new PGP key pair for document signing.
 *
 * Uses Ed25519 (Curve25519) by default for modern, fast signatures.
 * The private key is passphrase-protected using AES-256.
 *
 * @param name - Signer's display name
 * @param email - Signer's email address
 * @param passphrase - Passphrase to protect the private key
 * @returns Generated key pair with armored public and private keys
 */
export async function generateKeyPair(
  name: string,
  email: string,
  passphrase: string,
): Promise<KeyPair> {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: "ecc",
    curve: "curve25519",
    userIDs: [{ name, email }],
    passphrase,
    format: "armored",
  });

  const parsed = await openpgp.readKey({ armoredKey: publicKey });
  const fingerprint = parsed.getFingerprint().toUpperCase();

  return {
    fingerprint,
    publicKeyArmor: publicKey,
    privateKeyArmor: privateKey,
    name,
    email,
    createdAt: new Date(),
  };
}

// ---------------------------------------------------------------------------
// Key import
// ---------------------------------------------------------------------------

/**
 * Import an existing armored PGP private key.
 *
 * Validates the key is parseable and extracts metadata.
 * Does NOT decrypt the key — that only happens at signing time.
 *
 * @param armoredPrivateKey - ASCII-armored PGP private key
 * @returns Key metadata (fingerprint, name, email)
 */
export async function importPrivateKey(
  armoredPrivateKey: string,
): Promise<{ fingerprint: string; name: string; email: string; publicKeyArmor: string }> {
  const key = await openpgp.readPrivateKey({ armoredKey: armoredPrivateKey });
  const fingerprint = key.getFingerprint().toUpperCase();
  const user = await key.getPrimaryUser();
  const uid = user.user.userID;

  return {
    fingerprint,
    name: uid?.name ?? "",
    email: uid?.email ?? "",
    publicKeyArmor: key.toPublic().armor(),
  };
}

/**
 * Import an armored PGP public key.
 *
 * @param armoredPublicKey - ASCII-armored PGP public key
 * @returns Key fingerprint
 */
export async function importPublicKey(
  armoredPublicKey: string,
): Promise<{ fingerprint: string; name: string; email: string }> {
  const key = await openpgp.readKey({ armoredKey: armoredPublicKey });
  const fingerprint = key.getFingerprint().toUpperCase();
  const user = await key.getPrimaryUser();
  const uid = user.user.userID;

  return {
    fingerprint,
    name: uid?.name ?? "",
    email: uid?.email ?? "",
  };
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/**
 * Compute SHA-256 hash of binary data.
 *
 * Uses the Web Crypto API for hardware-accelerated hashing.
 *
 * @param data - Raw bytes to hash
 * @returns Hex-encoded SHA-256 digest
 */
export async function hashBytes(data: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/**
 * Sign a document hash with a PGP private key.
 *
 * The private key is decrypted in memory, used to sign, then the
 * decrypted key object is discarded. The original passphrase-protected
 * armored key is never modified.
 *
 * This creates a detached signature over the document's SHA-256 hash,
 * matching the Python engine's approach for cross-platform verification.
 *
 * @param documentData - Raw document bytes (PDF)
 * @param privateKeyArmor - Passphrase-protected armored private key
 * @param passphrase - Passphrase to unlock the key
 * @returns Signing result with armored signature and document hash
 */
export async function signDocument(
  documentData: ArrayBuffer,
  privateKeyArmor: string,
  passphrase: string,
): Promise<SigningResult> {
  // Hash the document
  const documentHash = await hashBytes(documentData);

  // Decrypt private key in memory
  const encryptedKey = await openpgp.readPrivateKey({
    armoredKey: privateKeyArmor,
  });
  const privateKey = await openpgp.decryptKey({
    privateKey: encryptedKey,
    passphrase,
  });

  // Sign the hash (same approach as Python engine — sign the hash string)
  const message = await openpgp.createMessage({
    binary: new TextEncoder().encode(documentHash),
  });
  const signedMessage = await openpgp.sign({
    message,
    signingKeys: privateKey,
  });

  const fingerprint = privateKey.getFingerprint().toUpperCase();

  return {
    signatureArmor: signedMessage as string,
    documentHash,
    fingerprint,
    signedAt: new Date(),
  };
}

/**
 * Sign raw bytes (e.g., a hash string) with a PGP key.
 *
 * Lower-level signing for custom workflows where the caller
 * manages hashing separately.
 *
 * @param data - Bytes to sign
 * @param privateKeyArmor - Passphrase-protected armored private key
 * @param passphrase - Passphrase to unlock the key
 * @returns Armored PGP signed message
 */
export async function signBytes(
  data: Uint8Array,
  privateKeyArmor: string,
  passphrase: string,
): Promise<string> {
  const encryptedKey = await openpgp.readPrivateKey({
    armoredKey: privateKeyArmor,
  });
  const privateKey = await openpgp.decryptKey({
    privateKey: encryptedKey,
    passphrase,
  });

  const message = await openpgp.createMessage({ binary: data });
  return (await openpgp.sign({ message, signingKeys: privateKey })) as string;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/**
 * Verify a PGP signature against a document.
 *
 * Checks that:
 * 1. The PGP signature is cryptographically valid
 * 2. The embedded hash matches the document's current hash
 *
 * @param documentData - Raw document bytes (current state)
 * @param signatureArmor - Armored PGP signed message
 * @param publicKeyArmor - Signer's armored public key
 * @param expectedHash - Optional expected document hash for comparison
 * @returns Verification result
 */
export async function verifySignature(
  documentData: ArrayBuffer | null,
  signatureArmor: string,
  publicKeyArmor: string,
  expectedHash?: string,
): Promise<VerificationResult> {
  try {
    const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmor });
    const message = await openpgp.readMessage({ armoredMessage: signatureArmor });
    const fingerprint = publicKey.getFingerprint().toUpperCase();

    // Verify the PGP signature
    const verification = await openpgp.verify({
      message,
      verificationKeys: publicKey,
    });

    const { verified, signature: sig } = verification.signatures[0];
    await verified; // throws on invalid signature

    // If document data provided, verify hash match
    if (documentData !== null) {
      const currentHash = await hashBytes(documentData);
      const signedData = verification.data;
      const embeddedHash =
        typeof signedData === "string"
          ? signedData
          : new TextDecoder().decode(signedData as Uint8Array);

      if (embeddedHash !== currentHash) {
        return {
          valid: false,
          fingerprint,
          error: "Document has been modified since signing",
        };
      }
    }

    // If expectedHash provided, verify it matches the embedded hash
    if (expectedHash) {
      const signedData = verification.data;
      const embeddedHash =
        typeof signedData === "string"
          ? signedData
          : new TextDecoder().decode(signedData as Uint8Array);
      if (embeddedHash !== expectedHash) {
        return {
          valid: false,
          fingerprint,
          error: "Hash mismatch with expected document hash",
        };
      }
    }

    const sigPacket = await sig;
    const signedAt = sigPacket.packets?.[0]
      ? new Date()
      : undefined;

    return { valid: true, fingerprint, signedAt };
  } catch (err) {
    return {
      valid: false,
      fingerprint: "",
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Extract the fingerprint from an armored key.
 *
 * @param armoredKey - Armored public or private key
 * @returns Uppercase hex fingerprint
 */
export async function extractFingerprint(armoredKey: string): Promise<string> {
  try {
    const key = await openpgp.readKey({ armoredKey });
    return key.getFingerprint().toUpperCase();
  } catch {
    // Try as private key
    const key = await openpgp.readPrivateKey({ armoredKey });
    return key.getFingerprint().toUpperCase();
  }
}
