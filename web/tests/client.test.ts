/**
 * Tests for SealClient — URL construction and request encoding.
 *
 * Network calls are intercepted so no real server is required.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SealClient } from "../src/client.js";

// ---------------------------------------------------------------------------
// Minimal fetch mock
// ---------------------------------------------------------------------------

type FetchResponse = {
  ok: boolean;
  status?: number;
  json?: () => Promise<unknown>;
  text?: () => Promise<string>;
  arrayBuffer?: () => Promise<ArrayBuffer>;
};

let _mockFetch: ReturnType<typeof vi.fn>;
let _capturedRequests: Array<{ url: string; init?: RequestInit }> = [];

beforeEach(() => {
  _capturedRequests = [];
  _mockFetch = vi.fn((url: string, init?: RequestInit) => {
    _capturedRequests.push({ url, init });
    return Promise.resolve<FetchResponse>({
      ok: true,
      status: 200,
      json: () => Promise.resolve([]),
      text: () => Promise.resolve(""),
      arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
    });
  });
  vi.stubGlobal("fetch", _mockFetch);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------
// Constructor / URL normalisation
// ---------------------------------------------------------------------------

describe("SealClient construction", () => {
  it("strips trailing slash from baseUrl", async () => {
    const client = new SealClient({ baseUrl: "https://seal.example.com/" });
    await client.listDocuments();
    expect(_capturedRequests[0].url).toBe(
      "https://seal.example.com/api/documents",
    );
  });

  it("works without trailing slash", async () => {
    const client = new SealClient({ baseUrl: "https://seal.example.com" });
    await client.listDocuments();
    expect(_capturedRequests[0].url).toBe(
      "https://seal.example.com/api/documents",
    );
  });

  it("includes Authorization header when token provided", async () => {
    const client = new SealClient({
      baseUrl: "https://seal.example.com",
      authToken: "my-token",
    });
    await client.listDocuments();
    const headers = _capturedRequests[0].init?.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer my-token");
  });

  it("omits Authorization header when no token", async () => {
    const client = new SealClient({ baseUrl: "https://seal.example.com" });
    await client.listDocuments();
    const headers = _capturedRequests[0].init?.headers as Record<string, string>;
    expect(headers["Authorization"]).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// listTemplates
// ---------------------------------------------------------------------------

describe("listTemplates", () => {
  it("GET /api/templates", async () => {
    const client = new SealClient({ baseUrl: "https://seal.example.com" });
    await client.listTemplates();
    expect(_capturedRequests[0].url).toBe(
      "https://seal.example.com/api/templates",
    );
  });
});

// ---------------------------------------------------------------------------
// listDocuments
// ---------------------------------------------------------------------------

describe("listDocuments", () => {
  it("GET /api/documents (no filter)", async () => {
    const client = new SealClient({ baseUrl: "https://seal.example.com" });
    await client.listDocuments();
    expect(_capturedRequests[0].url).toBe(
      "https://seal.example.com/api/documents",
    );
  });

  it("GET /api/documents?status=pending (with filter)", async () => {
    const client = new SealClient({ baseUrl: "https://seal.example.com" });
    await client.listDocuments("pending");
    expect(_capturedRequests[0].url).toBe(
      "https://seal.example.com/api/documents?status=pending",
    );
  });
});

// ---------------------------------------------------------------------------
// getDocument
// ---------------------------------------------------------------------------

describe("getDocument", () => {
  it("GET /api/documents/:id", async () => {
    const client = new SealClient({ baseUrl: "https://seal.example.com" });
    await client.getDocument("doc-123");
    expect(_capturedRequests[0].url).toBe(
      "https://seal.example.com/api/documents/doc-123",
    );
  });
});

// ---------------------------------------------------------------------------
// submitClientSignature
// ---------------------------------------------------------------------------

describe("submitClientSignature", () => {
  it("POST /api/documents/:id/sign-client with correct JSON body", async () => {
    const client = new SealClient({ baseUrl: "https://seal.example.com" });
    await client.submitClientSignature({
      documentId: "doc-abc",
      signerId: "signer-1",
      signatureArmor: "-----BEGIN PGP MESSAGE-----\n...",
      documentHash: "deadbeef" + "0".repeat(56),
      fingerprint: "ABCDEF".repeat(6) + "ABCD",
      fieldValues: { name: "Alice" },
    });

    const req = _capturedRequests[0];
    expect(req.url).toBe(
      "https://seal.example.com/api/documents/doc-abc/sign-client",
    );
    expect(req.init?.method).toBe("POST");

    const body = JSON.parse(req.init?.body as string);
    expect(body.signer_id).toBe("signer-1");
    expect(body.signature_armor).toContain("BEGIN PGP MESSAGE");
    expect(body.document_hash).toHaveLength(64);
    expect(body.field_values).toEqual({ name: "Alice" });
  });

  it("sends empty field_values when omitted", async () => {
    const client = new SealClient({ baseUrl: "https://seal.example.com" });
    await client.submitClientSignature({
      documentId: "doc-xyz",
      signerId: "signer-2",
      signatureArmor: "armor",
      documentHash: "a".repeat(64),
      fingerprint: "F".repeat(40),
    });

    const body = JSON.parse(_capturedRequests[0].init?.body as string);
    expect(body.field_values).toEqual({});
  });
});

// ---------------------------------------------------------------------------
// uploadPublicKey
// ---------------------------------------------------------------------------

describe("uploadPublicKey", () => {
  it("POST /api/keys with fingerprint and armor", async () => {
    const client = new SealClient({ baseUrl: "https://seal.example.com" });
    await client.uploadPublicKey("ABCD".repeat(10), "-----BEGIN PGP PUBLIC KEY BLOCK-----");

    const req = _capturedRequests[0];
    expect(req.url).toBe("https://seal.example.com/api/keys");
    expect(req.init?.method).toBe("POST");

    const body = JSON.parse(req.init?.body as string);
    expect(body.fingerprint).toBe("ABCD".repeat(10));
    expect(body.armor).toContain("BEGIN PGP PUBLIC KEY BLOCK");
  });
});

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

describe("error handling", () => {
  it("throws when server returns non-OK status", async () => {
    _mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      text: () => Promise.resolve("Document not found"),
    });

    const client = new SealClient({ baseUrl: "https://seal.example.com" });
    await expect(client.getDocument("missing")).rejects.toThrow("404");
  });
});
