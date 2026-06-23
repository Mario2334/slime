/**
 * E2E Crypto — Isomorphic authenticated encryption (AES-256-CTR + HMAC).
 *
 * Works in both Web Crypto API (browser / Cloudflare Workers) and Node.js.
 *
 * KEEP IN SYNC with packages/plugin/src/e2e-crypto.ts — the plugin vendors a
 * copy (instead of importing this package) to avoid dynamic `node:crypto`
 * imports that hang in some OpenClaw loaders. Any change here MUST be applied
 * identically to the vendored copy.
 *
 * Key design decisions:
 *   - Salt = "botschat-e2e:" + userId (domain-prefixed, deterministic)
 *   - PBKDF2-SHA256 with 310,000 iterations (OWASP 2023)
 *   - AES-256-CTR with nonce derived from contextId via HKDF-SHA256
 *   - Encrypt-then-MAC (HMAC-SHA256) for authenticated encryption:
 *       payload = [0x02 version][16-byte tag][AES-CTR ciphertext]
 *     A wrong key now FAILS the tag check and throws E2EAuthError instead of
 *     silently decrypting to garbage (the cause of "mojibake" agent replies).
 *     Legacy untagged ciphertext (v1) is still accepted on decrypt for backward
 *     compatibility with existing persisted history and not-yet-upgraded peers.
 *   - Each contextId MUST be globally unique and used ONLY ONCE per key
 */

// ---------------------------------------------------------------------------
// Runtime detection
// ---------------------------------------------------------------------------

const isNode =
  typeof globalThis.process !== "undefined" &&
  typeof globalThis.process.versions?.node === "string";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PBKDF2_ITERATIONS = 310_000;
const KEY_LENGTH = 32; // 256 bits
const NONCE_LENGTH = 16; // AES-CTR counter block
const SALT_PREFIX = "botschat-e2e:";
const MAC_VERSION = 0x02; // v2 = authenticated (encrypt-then-MAC)
const MAC_TAG_LENGTH = 16; // truncated HMAC-SHA256 tag
const MAC_KEY_INFO = "botschat-mac-v2"; // domain-separates the MAC subkey

// ---------------------------------------------------------------------------
// Helpers — encode / decode
// ---------------------------------------------------------------------------

function utf8Encode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function utf8Decode(buf: Uint8Array): string {
  return new TextDecoder().decode(buf);
}

/** Constant-time byte comparison (works in both runtimes). */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Thrown when an authenticated (v2) payload fails its MAC check — i.e. the key
 * is wrong or the ciphertext was tampered with. Callers should surface a clear
 * "couldn't decrypt" state rather than rendering the (unavailable) plaintext.
 */
export class E2EAuthError extends Error {
  constructor() {
    super("E2E authentication failed (wrong key or tampered ciphertext)");
    this.name = "E2E_AUTH_FAILED";
  }
}

// ---------------------------------------------------------------------------
// Web Crypto (browser + Cloudflare Workers) implementation
// ---------------------------------------------------------------------------

async function deriveKeyWeb(
  password: string,
  userId: string,
): Promise<Uint8Array> {
  const enc = utf8Encode(password);
  const salt = utf8Encode(SALT_PREFIX + userId);
  const baseKey = await crypto.subtle.importKey("raw", enc.buffer as ArrayBuffer, "PBKDF2", false, [
    "deriveBits",
  ]);
  const saltArr = new ArrayBuffer(salt.byteLength);
  new Uint8Array(saltArr).set(salt);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltArr, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    KEY_LENGTH * 8,
  );
  return new Uint8Array(bits);
}

/**
 * HKDF-SHA256 expand-only (single-step, info-only).
 * We only need 16 bytes so a single HMAC round suffices.
 */
async function hkdfNonceWeb(
  key: Uint8Array,
  contextId: string,
): Promise<Uint8Array> {
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    key.buffer as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const info = utf8Encode("nonce-" + contextId);
  // HKDF-Expand: T(1) = HMAC(PRK, info || 0x01)
  const input = new Uint8Array(info.length + 1);
  input.set(info);
  input[info.length] = 0x01;
  const full = await crypto.subtle.sign("HMAC", hmacKey, input.buffer as ArrayBuffer);
  return new Uint8Array(full).slice(0, NONCE_LENGTH);
}

async function deriveMacKeyWeb(masterKey: Uint8Array): Promise<Uint8Array> {
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    masterKey.buffer as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  // HMAC-SHA256 yields exactly 32 bytes — use it in full as the MAC subkey.
  const info = utf8Encode(MAC_KEY_INFO);
  const full = await crypto.subtle.sign("HMAC", hmacKey, info.buffer as ArrayBuffer);
  return new Uint8Array(full);
}

async function computeMacWeb(
  macKey: Uint8Array,
  contextId: string,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    macKey.buffer as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const ctx = utf8Encode(contextId);
  const data = new Uint8Array(ctx.length + 1 + ciphertext.length);
  data.set(ctx, 0);
  data[ctx.length] = 0x00; // separator prevents contextId/ciphertext ambiguity
  data.set(ciphertext, ctx.length + 1);
  const full = await crypto.subtle.sign("HMAC", hmacKey, data.buffer as ArrayBuffer);
  return new Uint8Array(full).slice(0, MAC_TAG_LENGTH);
}

async function encryptWeb(
  key: Uint8Array,
  plaintext: Uint8Array,
  contextId: string,
): Promise<Uint8Array> {
  const counter = await hkdfNonceWeb(key, contextId);
  const aesKey = await crypto.subtle.importKey(
    "raw",
    key.buffer as ArrayBuffer,
    { name: "AES-CTR" },
    false,
    ["encrypt"],
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-CTR", counter: new Uint8Array(counter).buffer as ArrayBuffer, length: 128 },
    aesKey,
    plaintext.buffer as ArrayBuffer,
  );
  return new Uint8Array(ciphertext);
}

async function decryptWeb(
  key: Uint8Array,
  ciphertext: Uint8Array,
  contextId: string,
): Promise<Uint8Array> {
  const counter = await hkdfNonceWeb(key, contextId);
  const aesKey = await crypto.subtle.importKey(
    "raw",
    key.buffer as ArrayBuffer,
    { name: "AES-CTR" },
    false,
    ["decrypt"],
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-CTR", counter: new Uint8Array(counter).buffer as ArrayBuffer, length: 128 },
    aesKey,
    ciphertext.buffer as ArrayBuffer,
  );
  return new Uint8Array(plaintext);
}

// ---------------------------------------------------------------------------
// Node.js implementation — use static imports resolved at load time.
// Dynamic `await import("node:crypto")` hangs in some extension loaders
// (e.g. OpenClaw gateway), so we resolve the modules eagerly when isNode.
// ---------------------------------------------------------------------------

// Node.js crypto modules — loaded eagerly.
// We use a global cache keyed by "__e2e_crypto" to avoid re-importing
// in environments where the module may be loaded multiple times.
let _nodeCrypto: typeof import("node:crypto") | null = null;
let _nodeUtil: typeof import("node:util") | null = null;

const _g = globalThis as Record<string, unknown>;
if (isNode && _g.__e2e_nodeCrypto) {
  _nodeCrypto = _g.__e2e_nodeCrypto as typeof import("node:crypto");
  _nodeUtil = _g.__e2e_nodeUtil as typeof import("node:util");
}

async function ensureNodeModules(): Promise<void> {
  if (_nodeCrypto && _nodeUtil) return;
  _nodeCrypto = await import("node:crypto");
  _nodeUtil = await import("node:util");
  _g.__e2e_nodeCrypto = _nodeCrypto;
  _g.__e2e_nodeUtil = _nodeUtil;
}

async function deriveKeyNode(
  password: string,
  userId: string,
): Promise<Uint8Array> {
  await ensureNodeModules();
  const pbkdf2Async = _nodeUtil!.promisify(_nodeCrypto!.pbkdf2);
  const salt = SALT_PREFIX + userId;
  const buf = await pbkdf2Async(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha256");
  return new Uint8Array(buf);
}

async function hkdfNonceNode(
  key: Uint8Array,
  contextId: string,
): Promise<Uint8Array> {
  await ensureNodeModules();
  const info = utf8Encode("nonce-" + contextId);
  const input = new Uint8Array(info.length + 1);
  input.set(info);
  input[info.length] = 0x01;
  const hmac = _nodeCrypto!.createHmac("sha256", Buffer.from(key));
  hmac.update(Buffer.from(input));
  const full = hmac.digest();
  return new Uint8Array(full.buffer, full.byteOffset, NONCE_LENGTH);
}

async function deriveMacKeyNode(masterKey: Uint8Array): Promise<Uint8Array> {
  await ensureNodeModules();
  const hmac = _nodeCrypto!.createHmac("sha256", Buffer.from(masterKey));
  hmac.update(MAC_KEY_INFO);
  return Uint8Array.from(hmac.digest()); // fresh 32-byte buffer, byteOffset 0
}

async function computeMacNode(
  macKey: Uint8Array,
  contextId: string,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  await ensureNodeModules();
  const hmac = _nodeCrypto!.createHmac("sha256", Buffer.from(macKey));
  // update() concatenates inputs for hashing — equivalent to one buffer of
  // (contextId || 0x00 || ciphertext), matching computeMacWeb exactly.
  hmac.update(Buffer.from(utf8Encode(contextId)));
  hmac.update(Buffer.from([0x00]));
  hmac.update(Buffer.from(ciphertext));
  const full = hmac.digest();
  return new Uint8Array(full.buffer, full.byteOffset, MAC_TAG_LENGTH);
}

async function encryptNode(
  key: Uint8Array,
  plaintext: Uint8Array,
  contextId: string,
): Promise<Uint8Array> {
  await ensureNodeModules();
  const iv = await hkdfNonceNode(key, contextId);
  const cipher = _nodeCrypto!.createCipheriv(
    "aes-256-ctr",
    Buffer.from(key),
    Buffer.from(iv),
  );
  const encrypted = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return new Uint8Array(encrypted);
}

async function decryptNode(
  key: Uint8Array,
  ciphertext: Uint8Array,
  contextId: string,
): Promise<Uint8Array> {
  await ensureNodeModules();
  const iv = await hkdfNonceNode(key, contextId);
  const decipher = _nodeCrypto!.createDecipheriv(
    "aes-256-ctr",
    Buffer.from(key),
    Buffer.from(iv),
  );
  const decrypted = Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]);
  return new Uint8Array(decrypted);
}

// ---------------------------------------------------------------------------
// Authenticated envelope: seal / open (encrypt-then-MAC, versioned)
// ---------------------------------------------------------------------------

/**
 * Encrypt then MAC. Returns [0x02][tag(16)][ciphertext].
 * `ciphertext` is extracted via .slice() so the raw CTR helpers — which read
 * `.buffer` (Web) — receive a standalone buffer (byteOffset 0).
 */
async function seal(
  key: Uint8Array,
  plaintext: Uint8Array,
  contextId: string,
): Promise<Uint8Array> {
  const macKey = isNode ? await deriveMacKeyNode(key) : await deriveMacKeyWeb(key);
  const ciphertext = isNode
    ? await encryptNode(key, plaintext, contextId)
    : await encryptWeb(key, plaintext, contextId);
  const tag = isNode
    ? await computeMacNode(macKey, contextId, ciphertext)
    : await computeMacWeb(macKey, contextId, ciphertext);
  const out = new Uint8Array(1 + MAC_TAG_LENGTH + ciphertext.length);
  out[0] = MAC_VERSION;
  out.set(tag, 1);
  out.set(ciphertext, 1 + MAC_TAG_LENGTH);
  return out;
}

/**
 * Verify MAC (if v2) then decrypt; otherwise treat as legacy v1 raw CTR.
 * Throws E2EAuthError on a tag mismatch (wrong key / tampering).
 */
async function open(
  key: Uint8Array,
  payload: Uint8Array,
  contextId: string,
): Promise<Uint8Array> {
  // v2 authenticated path: leading version byte + tag.
  if (payload.length >= 1 + MAC_TAG_LENGTH && payload[0] === MAC_VERSION) {
    const tag = payload.subarray(1, 1 + MAC_TAG_LENGTH);
    const ciphertext = payload.slice(1 + MAC_TAG_LENGTH); // copy → standalone buffer
    const macKey = isNode ? await deriveMacKeyNode(key) : await deriveMacKeyWeb(key);
    const expected = isNode
      ? await computeMacNode(macKey, contextId, ciphertext)
      : await computeMacWeb(macKey, contextId, ciphertext);
    if (!constantTimeEqual(tag, expected)) {
      throw new E2EAuthError();
    }
    return isNode ? decryptNode(key, ciphertext, contextId) : decryptWeb(key, ciphertext, contextId);
  }
  // Legacy v1 path (no version/tag): raw AES-CTR over the whole payload.
  // Kept so existing persisted history and not-yet-upgraded peers keep working.
  return isNode ? decryptNode(key, payload, contextId) : decryptWeb(key, payload, contextId);
}

// ---------------------------------------------------------------------------
// Public API — auto-selects implementation based on runtime
// ---------------------------------------------------------------------------

/**
 * Derive a 256-bit master key from the user's E2E password and userId.
 * Uses PBKDF2-SHA256 with 310,000 iterations; salt = "botschat-e2e:" + userId.
 */
export async function deriveKey(
  password: string,
  userId: string,
): Promise<Uint8Array> {
  return isNode ? deriveKeyNode(password, userId) : deriveKeyWeb(password, userId);
}

/**
 * Encrypt plaintext string using authenticated AES-256-CTR (encrypt-then-MAC).
 * Returns [0x02][16-byte tag][ciphertext] (plaintext length + 17 bytes).
 *
 * ⚠️  Each contextId MUST be globally unique and used ONLY ONCE per key.
 */
export async function encryptText(
  key: Uint8Array,
  plaintext: string,
  contextId: string,
): Promise<Uint8Array> {
  return seal(key, utf8Encode(plaintext), contextId);
}

/**
 * Decrypt an authenticated payload back to a plaintext string.
 * Throws E2EAuthError if the key is wrong or the payload was tampered with
 * (v2 payloads). Legacy v1 payloads are decrypted without verification.
 */
export async function decryptText(
  key: Uint8Array,
  ciphertext: Uint8Array,
  contextId: string,
): Promise<string> {
  const data = await open(key, ciphertext, contextId);
  return utf8Decode(data);
}

/**
 * Encrypt raw bytes using authenticated AES-256-CTR (encrypt-then-MAC).
 * Returns [0x02][16-byte tag][ciphertext] (input length + 17 bytes).
 */
export async function encryptBytes(
  key: Uint8Array,
  plaintext: Uint8Array,
  contextId: string,
): Promise<Uint8Array> {
  return seal(key, plaintext, contextId);
}

/**
 * Decrypt raw authenticated ciphertext bytes.
 * Throws E2EAuthError on a v2 tag mismatch.
 */
export async function decryptBytes(
  key: Uint8Array,
  ciphertext: Uint8Array,
  contextId: string,
): Promise<Uint8Array> {
  return open(key, ciphertext, contextId);
}

// ---------------------------------------------------------------------------
// Utility: base64 encode/decode for JSON transport
// ---------------------------------------------------------------------------

/** Encode binary to base64. */
export function toBase64(data: Uint8Array): string {
  // Works in both browser and Node
  if (typeof Buffer !== "undefined") {
    return Buffer.from(data).toString("base64");
  }
  let binary = "";
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary);
}

/** Decode base64 string to binary. */
export function fromBase64(b64: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    const buf = Buffer.from(b64, "base64");
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
