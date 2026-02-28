/**
 * SKSeal signing session — orchestrates the full client-side signing flow.
 *
 * The SigningSession ties together crypto, key store, and API client
 * into a single high-level interface for signing documents without
 * keys ever leaving the browser.
 *
 * Flow:
 *   1. Load or generate keys → stored in IndexedDB
 *   2. Fetch document + PDF from server
 *   3. Sign PDF hash locally with OpenPGP.js
 *   4. Submit signature to server (only signature, not key)
 *   5. Server records the signature and updates document status
 */
import { KeyStore } from "./keystore.js";
import { SealClient } from "./client.js";
import type { Document, KeyPair, SigningResult, StoredKey, VerificationResult } from "./types.js";
export interface SigningSessionOptions {
    /** SKSeal API base URL */
    apiUrl: string;
    /** Optional auth token */
    authToken?: string;
}
export declare class SigningSession {
    readonly keyStore: KeyStore;
    readonly client: SealClient;
    constructor(options: SigningSessionOptions);
    /**
     * Generate a new signing key pair and store it in the browser.
     *
     * The private key is passphrase-protected and stored in IndexedDB.
     * The public key is also uploaded to the SKSeal server for verification.
     *
     * @param name - Signer's display name
     * @param email - Signer's email
     * @param passphrase - Passphrase to protect the private key
     * @returns The generated key pair metadata
     */
    generateKey(name: string, email: string, passphrase: string): Promise<KeyPair>;
    /**
     * Import an existing PGP private key into the browser key store.
     *
     * @param armoredPrivateKey - ASCII-armored private key (passphrase-protected)
     * @returns Imported key metadata
     */
    importKey(armoredPrivateKey: string): Promise<StoredKey>;
    /** List all keys stored in the browser. */
    listKeys(): Promise<StoredKey[]>;
    /**
     * Sign a document — the full client-side flow.
     *
     * 1. Fetches the document metadata and PDF from the server
     * 2. Locates the signer by fingerprint match
     * 3. Loads the private key from IndexedDB
     * 4. Signs the PDF hash with OpenPGP.js (key stays in browser)
     * 5. Submits the signature to the server
     * 6. Returns the updated document
     *
     * @param documentId - ID of the document to sign
     * @param fingerprint - PGP fingerprint of the signing key
     * @param passphrase - Passphrase to unlock the private key
     * @param fieldValues - Optional field values filled by the signer
     * @returns Updated document with the new signature
     */
    sign(documentId: string, fingerprint: string, passphrase: string, fieldValues?: Record<string, string>): Promise<{
        document: Document;
        signingResult: SigningResult;
    }>;
    /**
     * Verify a document's signatures locally using OpenPGP.js.
     *
     * Downloads the PDF and verifies each signature against the
     * signer's public key without sending anything to the server.
     *
     * @param documentId - ID of the document to verify
     * @returns Per-signer verification results
     */
    verifyLocally(documentId: string): Promise<Map<string, VerificationResult>>;
    /**
     * Get the SHA-256 hash of a document's PDF.
     *
     * Useful for verifying document integrity before signing.
     *
     * @param documentId - Document ID
     * @returns Hex-encoded SHA-256 hash
     */
    getDocumentHash(documentId: string): Promise<string>;
}
//# sourceMappingURL=signing-session.d.ts.map