/**
 * SKSeal client-side cryptography — OpenPGP.js wrapper.
 *
 * All PGP operations happen in the browser. Private keys are decrypted
 * only in memory for the duration of a signing operation, then discarded.
 * Keys NEVER leave the client — only signatures are sent to the server.
 */
import type { KeyPair, SigningResult, VerificationResult } from "./types.js";
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
export declare function generateKeyPair(name: string, email: string, passphrase: string): Promise<KeyPair>;
/**
 * Import an existing armored PGP private key.
 *
 * Validates the key is parseable and extracts metadata.
 * Does NOT decrypt the key — that only happens at signing time.
 *
 * @param armoredPrivateKey - ASCII-armored PGP private key
 * @returns Key metadata (fingerprint, name, email)
 */
export declare function importPrivateKey(armoredPrivateKey: string): Promise<{
    fingerprint: string;
    name: string;
    email: string;
    publicKeyArmor: string;
}>;
/**
 * Import an armored PGP public key.
 *
 * @param armoredPublicKey - ASCII-armored PGP public key
 * @returns Key fingerprint
 */
export declare function importPublicKey(armoredPublicKey: string): Promise<{
    fingerprint: string;
    name: string;
    email: string;
}>;
/**
 * Compute SHA-256 hash of binary data.
 *
 * Uses the Web Crypto API for hardware-accelerated hashing.
 *
 * @param data - Raw bytes to hash
 * @returns Hex-encoded SHA-256 digest
 */
export declare function hashBytes(data: ArrayBuffer): Promise<string>;
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
export declare function signDocument(documentData: ArrayBuffer, privateKeyArmor: string, passphrase: string): Promise<SigningResult>;
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
export declare function signBytes(data: Uint8Array, privateKeyArmor: string, passphrase: string): Promise<string>;
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
export declare function verifySignature(documentData: ArrayBuffer | null, signatureArmor: string, publicKeyArmor: string, expectedHash?: string): Promise<VerificationResult>;
/**
 * Extract the fingerprint from an armored key.
 *
 * @param armoredKey - Armored public or private key
 * @returns Uppercase hex fingerprint
 */
export declare function extractFingerprint(armoredKey: string): Promise<string>;
//# sourceMappingURL=crypto.d.ts.map