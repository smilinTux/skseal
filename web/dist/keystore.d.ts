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
export declare class KeyStore {
    /**
     * Store a key pair in the browser's IndexedDB.
     *
     * The private key MUST be passphrase-protected before calling this.
     * This method does NOT encrypt — it stores whatever you give it.
     *
     * @param key - Key to store (fingerprint, armored keys, metadata)
     */
    store(key: StoredKey): Promise<void>;
    /**
     * Retrieve a key by fingerprint.
     *
     * @param fingerprint - 40-char hex PGP fingerprint (case-insensitive)
     * @returns Stored key or null if not found
     */
    get(fingerprint: string): Promise<StoredKey | null>;
    /**
     * List all stored keys (metadata only — no private key material in logs).
     *
     * @returns Array of stored keys
     */
    list(): Promise<StoredKey[]>;
    /**
     * Delete a key by fingerprint.
     *
     * @param fingerprint - Key to remove
     * @returns true if the key existed and was deleted
     */
    delete(fingerprint: string): Promise<boolean>;
    /**
     * Check if a key exists in the store.
     *
     * @param fingerprint - Key fingerprint to check
     */
    has(fingerprint: string): Promise<boolean>;
    /**
     * Clear all keys from the store.
     *
     * Destructive operation — use with caution.
     */
    clear(): Promise<void>;
}
//# sourceMappingURL=keystore.d.ts.map