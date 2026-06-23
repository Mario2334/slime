import { Capacitor } from "@capacitor/core";
import { Preferences } from "@capacitor/preferences";
import { deriveKey, encryptText, decryptText, encryptBytes, decryptBytes, toBase64, fromBase64 } from "e2e-crypto";

const STORAGE_KEY = "botschat_e2e_pwd_cache";
const KEY_CACHE_KEY = "botschat_e2e_key_cache"; // base64-encoded derived key
const KEY_CACHE_USERID = "botschat_e2e_key_userid"; // userId the cached key was derived for

const isNative = (() => {
  try {
    return Capacitor.isNativePlatform();
  } catch {
    return false;
  }
})();

let currentKey: Uint8Array | null = null;
let currentPassword: string | null = null;
let currentUserId: string | null = null;
const listeners: Set<() => void> = new Set();

/**
 * Cross-platform key-value storage.
 * Native → @capacitor/preferences (survives OS storage pressure / data clearing
 * better than WebView localStorage); web → localStorage (unchanged).
 */
const kv = {
  async get(key: string): Promise<string | null> {
    if (isNative) {
      const { value } = await Preferences.get({ key });
      return value;
    }
    return localStorage.getItem(key);
  },
  async set(key: string, value: string): Promise<void> {
    if (isNative) {
      await Preferences.set({ key, value });
    } else {
      localStorage.setItem(key, value);
    }
  },
  async remove(key: string): Promise<void> {
    if (isNative) {
      await Preferences.remove({ key });
    } else {
      localStorage.removeItem(key);
    }
  },
};

// Web-only synchronous warm restore (native restores async via loadSavedPassword
// on auth.ok). The cached key is only trusted once loadSavedPassword verifies it
// belongs to the current user — and the encrypt-then-MAC crypto now makes a
// stale/wrong key fail gracefully instead of rendering as mojibake.
if (!isNative) {
  try {
    const cachedKey = localStorage.getItem(KEY_CACHE_KEY);
    if (cachedKey) {
      currentKey = fromBase64(cachedKey);
      currentPassword = localStorage.getItem(STORAGE_KEY);
      currentUserId = localStorage.getItem(KEY_CACHE_USERID);
    }
  } catch {
    /* ignore */
  }
}

export const E2eService = {
  /**
   * Subscribe to key state changes. Returns unsubscribe function.
   */
  subscribe(cb: () => void): () => void {
    listeners.add(cb);
    return () => listeners.delete(cb);
  },

  /**
   * Notify all listeners.
   */
  notify() {
    listeners.forEach((cb) => cb());
  },

  /**
   * Set the E2E password and derive the key.
   * Optionally persist the password and derived key (scoped to userId).
   */
  async setPassword(password: string, userId: string, remember: boolean): Promise<void> {
    if (!password) {
      currentKey = null;
      currentPassword = null;
      currentUserId = null;
      await kv.remove(STORAGE_KEY);
      await kv.remove(KEY_CACHE_KEY);
      await kv.remove(KEY_CACHE_USERID);
      this.notify();
      return;
    }

    try {
      currentKey = await deriveKey(password, userId);
      currentPassword = password;
      currentUserId = userId;
      if (remember) {
        await kv.set(STORAGE_KEY, password);
        await kv.set(KEY_CACHE_KEY, toBase64(currentKey));
        await kv.set(KEY_CACHE_USERID, userId);
      } else {
        await kv.remove(STORAGE_KEY);
        await kv.remove(KEY_CACHE_KEY);
        await kv.remove(KEY_CACHE_USERID);
      }
      this.notify();
    } catch (err) {
      console.error("Failed to derive E2E key:", err);
      throw err;
    }
  },

  /**
   * Clear the key and password from memory and storage.
   */
  async clear(): Promise<void> {
    currentKey = null;
    currentPassword = null;
    currentUserId = null;
    await kv.remove(STORAGE_KEY);
    await kv.remove(KEY_CACHE_KEY);
    await kv.remove(KEY_CACHE_USERID);
    this.notify();
  },

  /**
   * Check if a key is loaded.
   */
  hasKey(): boolean {
    return !!currentKey;
  },

  /**
   * Check if a key is loaded AND derived for the given user.
   */
  hasKeyForUser(userId?: string): boolean {
    return !!currentKey && (!userId || currentUserId === userId);
  },

  /**
   * Best-effort synchronous check for a saved password.
   * Web inspects localStorage; native reflects in-memory state (populated once
   * loadSavedPassword runs on auth.ok).
   */
  hasSavedPassword(): boolean {
    if (isNative) return !!currentPassword;
    try {
      return !!localStorage.getItem(STORAGE_KEY);
    } catch {
      return false;
    }
  },

  /**
   * Load the E2E key for the given user. Uses the cached derived key ONLY when it
   * was derived for the SAME user; otherwise discards the stale cache and
   * re-derives via PBKDF2. This prevents the stale-key mojibake that occurred
   * when the userId changed (e.g. env-seeded account switch).
   * Returns true if a key is now available.
   */
  async loadSavedPassword(userId: string): Promise<boolean> {
    if (currentKey && currentUserId === userId) return true;
    const savedPwd = await kv.get(STORAGE_KEY);
    if (!savedPwd) return false;
    try {
      const cachedKeyB64 = await kv.get(KEY_CACHE_KEY);
      const cachedUid = await kv.get(KEY_CACHE_USERID);
      if (cachedKeyB64 && cachedUid === userId) {
        // Fast path: reuse the cached derived key (no PBKDF2).
        currentKey = fromBase64(cachedKeyB64);
        currentPassword = savedPwd;
        currentUserId = userId;
      } else {
        // Stale or missing cache for this user — re-derive and re-cache.
        await this.setPassword(savedPwd, userId, true);
      }
      this.notify();
      return true;
    } catch {
      return false;
    }
  },

  /**
   * Encrypt text using the current key.
   * If contextId is provided, uses it as the nonce source (for preserving
   * existing messageIds). Otherwise generates a random UUID.
   * Returns { ciphertext: base64, messageId: string }
   */
  async encrypt(text: string, contextId?: string): Promise<{ ciphertext: string; messageId: string }> {
    if (!currentKey) throw new Error("E2E key not set");
    const messageId = contextId || crypto.randomUUID();
    const encrypted = await encryptText(currentKey, text, messageId);
    return { ciphertext: toBase64(encrypted), messageId };
  },

  /**
   * Decrypt text (base64) using the current key and messageId (contextId).
   * Throws if the key is wrong (authenticated encryption).
   */
  async decrypt(ciphertextBase64: string, messageId: string): Promise<string> {
    if (!currentKey) throw new Error("E2E key not set");
    const ciphertext = fromBase64(ciphertextBase64);
    return decryptText(currentKey, ciphertext, messageId);
  },

  /**
   * Get the current E2E password (in memory). Returns null if not set.
   */
  getPassword(): string | null {
    return currentPassword;
  },

  /**
   * Encrypt raw binary data (e.g., an image file).
   * Returns { encrypted: Uint8Array, contextId: string }.
   */
  async encryptMedia(data: Uint8Array, contextId?: string): Promise<{ encrypted: Uint8Array; contextId: string }> {
    if (!currentKey) throw new Error("E2E key not set");
    const cid = contextId || crypto.randomUUID();
    const encrypted = await encryptBytes(currentKey, data, cid);
    return { encrypted, contextId: cid };
  },

  /**
   * Decrypt raw binary data (e.g., an encrypted image).
   * Throws if the key is wrong (authenticated encryption).
   */
  async decryptMedia(encrypted: Uint8Array, contextId: string): Promise<Uint8Array> {
    if (!currentKey) throw new Error("E2E key not set");
    return decryptBytes(currentKey, encrypted, contextId);
  },

  /**
   * Decrypt bytes (base64) -> Uint8Array.
   */
  async decryptBytesLegacy(ciphertextBase64: string, messageId: string): Promise<Uint8Array> {
    if (!currentKey) throw new Error("E2E key not set");
    const ciphertext = fromBase64(ciphertextBase64);
    const plainStr = await decryptText(currentKey, ciphertext, messageId);
    return new TextEncoder().encode(plainStr);
  }
};
