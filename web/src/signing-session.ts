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

import {
  generateKeyPair,
  importPrivateKey,
  signDocument,
  verifySignature,
  hashBytes,
} from "./crypto.js";
import { KeyStore } from "./keystore.js";
import { SealClient } from "./client.js";
import type {
  Document,
  KeyPair,
  SigningResult,
  StoredKey,
  VerificationResult,
} from "./types.js";

export interface SigningSessionOptions {
  /** SKSeal API base URL */
  apiUrl: string;
  /** Optional auth token */
  authToken?: string;
}

export class SigningSession {
  readonly keyStore: KeyStore;
  readonly client: SealClient;

  constructor(options: SigningSessionOptions) {
    this.keyStore = new KeyStore();
    this.client = new SealClient({
      baseUrl: options.apiUrl,
      authToken: options.authToken,
    });
  }

  // -----------------------------------------------------------------------
  // Key management
  // -----------------------------------------------------------------------

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
  async generateKey(
    name: string,
    email: string,
    passphrase: string,
  ): Promise<KeyPair> {
    const keyPair = await generateKeyPair(name, email, passphrase);

    // Store in browser
    await this.keyStore.store({
      fingerprint: keyPair.fingerprint,
      publicKeyArmor: keyPair.publicKeyArmor,
      privateKeyArmor: keyPair.privateKeyArmor,
      name: keyPair.name,
      email: keyPair.email,
      createdAt: keyPair.createdAt.toISOString(),
    });

    // Upload public key to server
    await this.client.uploadPublicKey(
      keyPair.fingerprint,
      keyPair.publicKeyArmor,
    );

    return keyPair;
  }

  /**
   * Import an existing PGP private key into the browser key store.
   *
   * @param armoredPrivateKey - ASCII-armored private key (passphrase-protected)
   * @returns Imported key metadata
   */
  async importKey(armoredPrivateKey: string): Promise<StoredKey> {
    const meta = await importPrivateKey(armoredPrivateKey);

    const stored: StoredKey = {
      fingerprint: meta.fingerprint,
      publicKeyArmor: meta.publicKeyArmor,
      privateKeyArmor: armoredPrivateKey,
      name: meta.name,
      email: meta.email,
      createdAt: new Date().toISOString(),
    };

    await this.keyStore.store(stored);
    await this.client.uploadPublicKey(meta.fingerprint, meta.publicKeyArmor);

    return stored;
  }

  /** List all keys stored in the browser. */
  async listKeys(): Promise<StoredKey[]> {
    return this.keyStore.list();
  }

  // -----------------------------------------------------------------------
  // Signing
  // -----------------------------------------------------------------------

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
  async sign(
    documentId: string,
    fingerprint: string,
    passphrase: string,
    fieldValues?: Record<string, string>,
  ): Promise<{ document: Document; signingResult: SigningResult }> {
    // 1. Get document metadata
    const doc = await this.client.getDocument(documentId);

    // 2. Find the signer
    const fp = fingerprint.toUpperCase();
    const signer = doc.signers.find((s) =>
      s.fingerprint.toUpperCase().startsWith(fp) ||
      fp.startsWith(s.fingerprint.toUpperCase()),
    );
    if (!signer) {
      throw new Error(`No signer with fingerprint ${fp} found in document`);
    }

    // 3. Load private key from browser store
    const storedKey = await this.keyStore.get(fp);
    if (!storedKey) {
      throw new Error(
        `Private key ${fp.slice(0, 16)}... not found in browser key store`,
      );
    }

    // 4. Download PDF and sign locally
    const pdfData = await this.client.downloadPdf(documentId);
    const signingResult = await signDocument(
      pdfData,
      storedKey.privateKeyArmor,
      passphrase,
    );

    // 5. Submit signature to server
    const updatedDoc = await this.client.submitClientSignature({
      documentId,
      signerId: signer.signer_id,
      signatureArmor: signingResult.signatureArmor,
      documentHash: signingResult.documentHash,
      fingerprint: signingResult.fingerprint,
      fieldValues,
    });

    return { document: updatedDoc, signingResult };
  }

  // -----------------------------------------------------------------------
  // Verification
  // -----------------------------------------------------------------------

  /**
   * Verify a document's signatures locally using OpenPGP.js.
   *
   * Downloads the PDF and verifies each signature against the
   * signer's public key without sending anything to the server.
   *
   * @param documentId - ID of the document to verify
   * @returns Per-signer verification results
   */
  async verifyLocally(
    documentId: string,
  ): Promise<Map<string, VerificationResult>> {
    const doc = await this.client.getDocument(documentId);
    const pdfData = await this.client.downloadPdf(documentId);

    const results = new Map<string, VerificationResult>();

    for (const record of doc.signatures) {
      // Try to get public key from local store or from the signer record
      const storedKey = await this.keyStore.get(record.fingerprint);
      const signer = doc.signers.find(
        (s) => s.signer_id === record.signer_id,
      );

      const publicKeyArmor =
        storedKey?.publicKeyArmor ?? signer?.public_key_armor;

      if (!publicKeyArmor) {
        results.set(record.signer_id, {
          valid: false,
          fingerprint: record.fingerprint,
          error: `No public key for fingerprint ${record.fingerprint.slice(0, 16)}...`,
        });
        continue;
      }

      const result = await verifySignature(
        pdfData,
        record.signature_armor,
        publicKeyArmor,
        record.document_hash,
      );
      results.set(record.signer_id, result);
    }

    return results;
  }

  /**
   * Get the SHA-256 hash of a document's PDF.
   *
   * Useful for verifying document integrity before signing.
   *
   * @param documentId - Document ID
   * @returns Hex-encoded SHA-256 hash
   */
  async getDocumentHash(documentId: string): Promise<string> {
    const pdfData = await this.client.downloadPdf(documentId);
    return hashBytes(pdfData);
  }
}
