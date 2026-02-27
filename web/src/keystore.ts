/**
 * SKSeal browser key store — IndexedDB-backed PGP key management.
 *
 * Private keys are stored passphrase-protected (OpenPGP encrypted armor).
 * They are NEVER decrypted at rest — only in memory during signing.
 *
 * Storage layout:
 *   Database: "skseal-keys"
 *   Store: "keys" — indexed by fingerprint
 *
 * This module gracefully degrades: if IndexedDB is unavailable (e.g.,
 * in Node.js tests), it falls back to an in-memory Map.
 */

import type { StoredKey } from "./types.js";

const DB_NAME = "skseal-keys";
const DB_VERSION = 1;
const STORE_NAME = "keys";

// ---------------------------------------------------------------------------
// IndexedDB helpers
// ---------------------------------------------------------------------------

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "fingerprint" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function idbAvailable(): boolean {
  return typeof indexedDB !== "undefined";
}

// ---------------------------------------------------------------------------
// In-memory fallback (for Node.js / SSR / tests)
// ---------------------------------------------------------------------------

const memoryStore = new Map<string, StoredKey>();

// ---------------------------------------------------------------------------
// KeyStore class
// ---------------------------------------------------------------------------

export class KeyStore {
  /**
   * Store a key pair in the browser's IndexedDB.
   *
   * The private key MUST be passphrase-protected before calling this.
   * This method does NOT encrypt — it stores whatever you give it.
   *
   * @param key - Key to store (fingerprint, armored keys, metadata)
   */
  async store(key: StoredKey): Promise<void> {
    if (!idbAvailable()) {
      memoryStore.set(key.fingerprint, key);
      return;
    }

    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).put(key);
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => {
        db.close();
        reject(tx.error);
      };
    });
  }

  /**
   * Retrieve a key by fingerprint.
   *
   * @param fingerprint - 40-char hex PGP fingerprint (case-insensitive)
   * @returns Stored key or null if not found
   */
  async get(fingerprint: string): Promise<StoredKey | null> {
    const fp = fingerprint.toUpperCase();

    if (!idbAvailable()) {
      return memoryStore.get(fp) ?? null;
    }

    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const request = tx.objectStore(STORE_NAME).get(fp);
      request.onsuccess = () => {
        db.close();
        resolve(request.result ?? null);
      };
      request.onerror = () => {
        db.close();
        reject(request.error);
      };
    });
  }

  /**
   * List all stored keys (metadata only — no private key material in logs).
   *
   * @returns Array of stored keys
   */
  async list(): Promise<StoredKey[]> {
    if (!idbAvailable()) {
      return Array.from(memoryStore.values());
    }

    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const request = tx.objectStore(STORE_NAME).getAll();
      request.onsuccess = () => {
        db.close();
        resolve(request.result);
      };
      request.onerror = () => {
        db.close();
        reject(request.error);
      };
    });
  }

  /**
   * Delete a key by fingerprint.
   *
   * @param fingerprint - Key to remove
   * @returns true if the key existed and was deleted
   */
  async delete(fingerprint: string): Promise<boolean> {
    const fp = fingerprint.toUpperCase();

    if (!idbAvailable()) {
      return memoryStore.delete(fp);
    }

    const existing = await this.get(fp);
    if (!existing) return false;

    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).delete(fp);
      tx.oncomplete = () => {
        db.close();
        resolve(true);
      };
      tx.onerror = () => {
        db.close();
        reject(tx.error);
      };
    });
  }

  /**
   * Check if a key exists in the store.
   *
   * @param fingerprint - Key fingerprint to check
   */
  async has(fingerprint: string): Promise<boolean> {
    return (await this.get(fingerprint)) !== null;
  }

  /**
   * Clear all keys from the store.
   *
   * Destructive operation — use with caution.
   */
  async clear(): Promise<void> {
    if (!idbAvailable()) {
      memoryStore.clear();
      return;
    }

    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).clear();
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => {
        db.close();
        reject(tx.error);
      };
    });
  }
}
