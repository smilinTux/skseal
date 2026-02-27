/**
 * SKSeal API client — browser-safe HTTP client for the FastAPI backend.
 *
 * This client handles communication between the browser signing SDK
 * and the SKSeal server. It sends ONLY signatures and public data —
 * never private keys.
 */

import type {
  ClientSignRequest,
  Document,
  Template,
  AuditEntry,
} from "./types.js";

export interface SealClientOptions {
  /** Base URL of the SKSeal API (e.g., "https://seal.example.com") */
  baseUrl: string;
  /** Optional auth token for authenticated requests */
  authToken?: string;
}

export class SealClient {
  private baseUrl: string;
  private authToken?: string;

  constructor(options: SealClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.authToken = options.authToken;
  }

  // -----------------------------------------------------------------------
  // Internal
  // -----------------------------------------------------------------------

  private async request<T>(
    path: string,
    init?: RequestInit,
  ): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(this.authToken ? { Authorization: `Bearer ${this.authToken}` } : {}),
    };

    const response = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: { ...headers, ...init?.headers },
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`SKSeal API error ${response.status}: ${body}`);
    }

    return response.json();
  }

  // -----------------------------------------------------------------------
  // Templates
  // -----------------------------------------------------------------------

  /** List all document templates. */
  async listTemplates(): Promise<Template[]> {
    return this.request<Template[]>("/api/templates");
  }

  /** Get a template by ID. */
  async getTemplate(templateId: string): Promise<Template> {
    return this.request<Template>(`/api/templates/${templateId}`);
  }

  // -----------------------------------------------------------------------
  // Documents
  // -----------------------------------------------------------------------

  /** List documents, optionally filtered by status. */
  async listDocuments(status?: string): Promise<Document[]> {
    const qs = status ? `?status=${encodeURIComponent(status)}` : "";
    return this.request<Document[]>(`/api/documents${qs}`);
  }

  /** Get a document by ID. */
  async getDocument(documentId: string): Promise<Document> {
    return this.request<Document>(`/api/documents/${documentId}`);
  }

  /** Download the source PDF for a document as ArrayBuffer. */
  async downloadPdf(documentId: string): Promise<ArrayBuffer> {
    const headers: Record<string, string> = this.authToken
      ? { Authorization: `Bearer ${this.authToken}` }
      : {};

    const response = await fetch(
      `${this.baseUrl}/api/documents/${documentId}/pdf`,
      { headers },
    );

    if (!response.ok) {
      throw new Error(`Failed to download PDF: ${response.status}`);
    }

    return response.arrayBuffer();
  }

  /** Get the audit trail for a document. */
  async getAuditTrail(documentId: string): Promise<AuditEntry[]> {
    return this.request<AuditEntry[]>(
      `/api/documents/${documentId}/audit`,
    );
  }

  // -----------------------------------------------------------------------
  // Client-side signing submission
  // -----------------------------------------------------------------------

  /**
   * Submit a client-side signature to the server.
   *
   * This is the key endpoint for the client-side signing flow:
   * 1. Client downloads PDF from server
   * 2. Client signs hash locally with OpenPGP.js (keys never leave browser)
   * 3. Client submits the signature + hash to this endpoint
   * 4. Server verifies the signature and records it
   *
   * NOTE: This endpoint needs to be added to the Python API.
   * Until then, this method prepares the payload for manual integration.
   */
  async submitClientSignature(req: ClientSignRequest): Promise<Document> {
    return this.request<Document>(
      `/api/documents/${req.documentId}/sign-client`,
      {
        method: "POST",
        body: JSON.stringify({
          signer_id: req.signerId,
          signature_armor: req.signatureArmor,
          document_hash: req.documentHash,
          fingerprint: req.fingerprint,
          field_values: req.fieldValues ?? {},
        }),
      },
    );
  }

  // -----------------------------------------------------------------------
  // Key management
  // -----------------------------------------------------------------------

  /**
   * Upload a public key to the server's key cache.
   *
   * The server needs public keys to verify signatures. This uploads
   * the public key (never the private key) for future verification.
   */
  async uploadPublicKey(
    fingerprint: string,
    publicKeyArmor: string,
  ): Promise<void> {
    await this.request("/api/keys", {
      method: "POST",
      body: JSON.stringify({ fingerprint, armor: publicKeyArmor }),
    });
  }

  // -----------------------------------------------------------------------
  // Verification
  // -----------------------------------------------------------------------

  /** Request server-side verification of a document's signatures. */
  async verifyDocument(
    documentId: string,
    publicKeys?: Record<string, string>,
  ): Promise<Array<{ signer_id: string; valid: boolean }>> {
    return this.request(
      `/api/documents/${documentId}/verify`,
      {
        method: "POST",
        body: JSON.stringify({ public_keys: publicKeys ?? {} }),
      },
    );
  }
}
