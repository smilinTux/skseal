/**
 * SKSeal API client — browser-safe HTTP client for the FastAPI backend.
 *
 * This client handles communication between the browser signing SDK
 * and the SKSeal server. It sends ONLY signatures and public data —
 * never private keys.
 */
import type { ClientSignRequest, Document, Template, AuditEntry } from "./types.js";
export interface SealClientOptions {
    /** Base URL of the SKSeal API (e.g., "https://seal.example.com") */
    baseUrl: string;
    /** Optional auth token for authenticated requests */
    authToken?: string;
}
export declare class SealClient {
    private baseUrl;
    private authToken?;
    constructor(options: SealClientOptions);
    private request;
    /** List all document templates. */
    listTemplates(): Promise<Template[]>;
    /** Get a template by ID. */
    getTemplate(templateId: string): Promise<Template>;
    /** List documents, optionally filtered by status. */
    listDocuments(status?: string): Promise<Document[]>;
    /** Get a document by ID. */
    getDocument(documentId: string): Promise<Document>;
    /** Download the source PDF for a document as ArrayBuffer. */
    downloadPdf(documentId: string): Promise<ArrayBuffer>;
    /** Get the audit trail for a document. */
    getAuditTrail(documentId: string): Promise<AuditEntry[]>;
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
    submitClientSignature(req: ClientSignRequest): Promise<Document>;
    /**
     * Upload a public key to the server's key cache.
     *
     * The server needs public keys to verify signatures. This uploads
     * the public key (never the private key) for future verification.
     */
    uploadPublicKey(fingerprint: string, publicKeyArmor: string): Promise<void>;
    /** Request server-side verification of a document's signatures. */
    verifyDocument(documentId: string, publicKeys?: Record<string, string>): Promise<Array<{
        signer_id: string;
        valid: boolean;
    }>>;
}
//# sourceMappingURL=client.d.ts.map