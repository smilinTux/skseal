/**
 * Tests for SKSeal KeyStore.
 *
 * In Node.js (no IndexedDB), the store uses an in-memory Map fallback.
 * These tests verify the full CRUD lifecycle in that environment.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { KeyStore } from "../src/keystore.js";
import type { StoredKey } from "../src/types.js";

function makeKey(fingerprint: string): StoredKey {
  return {
    fingerprint,
    publicKeyArmor: `-----BEGIN PGP PUBLIC KEY BLOCK-----\nFP:${fingerprint}\n-----END PGP PUBLIC KEY BLOCK-----`,
    privateKeyArmor: `-----BEGIN PGP PRIVATE KEY BLOCK-----\nFP:${fingerprint}\n-----END PGP PRIVATE KEY BLOCK-----`,
    name: `User ${fingerprint.slice(0, 8)}`,
    email: `user-${fingerprint.slice(0, 8)}@test.example`,
    createdAt: new Date().toISOString(),
  };
}

describe("KeyStore (in-memory fallback)", () => {
  let store: KeyStore;

  beforeEach(async () => {
    store = new KeyStore();
    await store.clear();
  });

  it("stores and retrieves a key by fingerprint", async () => {
    const key = makeKey("AAAA".repeat(10));
    await store.store(key);
    const retrieved = await store.get("AAAA".repeat(10));
    expect(retrieved).not.toBeNull();
    expect(retrieved!.fingerprint).toBe("AAAA".repeat(10));
    expect(retrieved!.name).toBe(key.name);
  });

  it("retrieves key case-insensitively", async () => {
    const key = makeKey("ABCDEF".repeat(6) + "ABCD");
    const fp = key.fingerprint;
    await store.store(key);
    const retrieved = await store.get(fp.toLowerCase());
    expect(retrieved).not.toBeNull();
    expect(retrieved!.fingerprint).toBe(fp);
  });

  it("returns null for unknown fingerprint", async () => {
    const result = await store.get("FFFF".repeat(10));
    expect(result).toBeNull();
  });

  it("has() returns true/false correctly", async () => {
    const key = makeKey("BBBB".repeat(10));
    expect(await store.has(key.fingerprint)).toBe(false);
    await store.store(key);
    expect(await store.has(key.fingerprint)).toBe(true);
  });

  it("lists all stored keys", async () => {
    const k1 = makeKey("CCCC".repeat(10));
    const k2 = makeKey("DDDD".repeat(10));
    await store.store(k1);
    await store.store(k2);
    const all = await store.list();
    expect(all.length).toBeGreaterThanOrEqual(2);
    const fps = all.map((k) => k.fingerprint);
    expect(fps).toContain(k1.fingerprint);
    expect(fps).toContain(k2.fingerprint);
  });

  it("deletes a key", async () => {
    const key = makeKey("EEEE".repeat(10));
    await store.store(key);
    const deleted = await store.delete(key.fingerprint);
    expect(deleted).toBe(true);
    expect(await store.get(key.fingerprint)).toBeNull();
  });

  it("delete returns false for non-existent key", async () => {
    const deleted = await store.delete("FFFF".repeat(10));
    expect(deleted).toBe(false);
  });

  it("overwrites key with same fingerprint", async () => {
    const fp = "1234".repeat(10);
    const original = makeKey(fp);
    await store.store(original);

    const updated = { ...original, name: "Updated Name" };
    await store.store(updated);

    const retrieved = await store.get(fp);
    expect(retrieved!.name).toBe("Updated Name");
  });

  it("clear removes all keys", async () => {
    await store.store(makeKey("AAAA".repeat(10)));
    await store.store(makeKey("BBBB".repeat(10)));
    await store.clear();
    const all = await store.list();
    expect(all).toHaveLength(0);
  });
});
