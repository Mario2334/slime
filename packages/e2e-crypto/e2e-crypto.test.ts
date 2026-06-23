/**
 * E2E Crypto tests.
 * Run: npx tsx packages/e2e-crypto/e2e-crypto.test.ts
 *
 * NOTE: this suite runs under Node, so encrypt/decrypt exercise the Node
 * crypto path. The Web (Web Crypto) path is the symmetric construction and is
 * covered by the browser smoke test (./scripts/dev.sh). Cross-impl correctness
 * (Node-encrypt → Web-decrypt) is therefore verified end-to-end there.
 */

import assert from "node:assert";
import {
  deriveKey,
  encryptText,
  decryptText,
  encryptBytes,
  decryptBytes,
  toBase64,
  E2EAuthError,
} from "./e2e-crypto.js";

const password = "test-password";
const userId = "u_test_user_123";

const MAC_OVERHEAD = 1 + 16; // version byte + 16-byte HMAC tag

async function testKeyDerivation() {
  const key1 = await deriveKey(password, userId);
  const key2 = await deriveKey(password, userId);
  assert.strictEqual(key1.length, 32, "Key must be 32 bytes");
  assert.strictEqual(
    toBase64(key1),
    toBase64(key2),
    "CRYPTO-1: Same password+userId must yield same key"
  );
  console.log("  ✅ CRYPTO-1 deriveKey(password, userId) consistent");
}

async function testRoundtrip() {
  const key = await deriveKey(password, userId);
  const plaintext = "Hello 世界 🔐";
  const contextId = "msg-abc-123";
  const ciphertext = await encryptText(key, plaintext, contextId);
  const decrypted = await decryptText(key, ciphertext, contextId);
  assert.strictEqual(
    decrypted,
    plaintext,
    "CRYPTO-2: decrypt(encrypt(plaintext)) === plaintext"
  );
  console.log("  ✅ CRYPTO-2 encrypt/decrypt roundtrip (v2 authenticated)");
}

async function testCiphertextFormatAndLength() {
  const key = await deriveKey(password, userId);
  const plaintext = "short";
  const contextId = "ctx-1";
  const ciphertext = await encryptText(key, plaintext, contextId);
  const plainBytes = new TextEncoder().encode(plaintext);
  assert.strictEqual(
    ciphertext.length,
    plainBytes.length + MAC_OVERHEAD,
    "CRYPTO-3: v2 ciphertext = plaintext + 17 bytes (version + tag)"
  );
  assert.strictEqual(ciphertext[0], 0x02, "CRYPTO-3: leading version byte is 0x02");
  console.log("  ✅ CRYPTO-3 v2 ciphertext format and length");
}

async function testWrongKeyOrContextIdThrows() {
  const key = await deriveKey(password, userId);
  const plaintext = "secret";
  const contextId = "msg-1";
  const ciphertext = await encryptText(key, plaintext, contextId);

  // Wrong key MUST throw E2EAuthError (no more silent garbage).
  const wrongKey = await deriveKey("wrong-password", userId);
  await assert.rejects(
    () => decryptText(wrongKey, ciphertext, contextId),
    (err: unknown) => err instanceof E2EAuthError && err.name === "E2E_AUTH_FAILED",
    "CRYPTO-4: Wrong key must throw E2EAuthError"
  );

  // Wrong contextId MUST throw E2EAuthError (tag is bound to contextId).
  await assert.rejects(
    () => decryptText(key, ciphertext, "wrong-context-id"),
    (err: unknown) => err instanceof E2EAuthError,
    "CRYPTO-4: Wrong contextId must throw E2EAuthError"
  );
  console.log("  ✅ CRYPTO-4 wrong key/contextId throws E2EAuthError");
}

async function testDeterministicSameContextId() {
  const key = await deriveKey(password, userId);
  const plaintext = "same";
  const contextId = "ctx-deterministic";
  const ct1 = await encryptText(key, plaintext, contextId);
  const ct2 = await encryptText(key, plaintext, contextId);
  assert.strictEqual(
    toBase64(ct1),
    toBase64(ct2),
    "CRYPTO-5: Same plaintext + contextId must yield same ciphertext"
  );
  console.log("  ✅ CRYPTO-5 deterministic encryption for same contextId");
}

async function testShortPlaintext() {
  const key = await deriveKey(password, userId);
  const plaintext = "ab"; // 2 bytes UTF-8
  const contextId = "msg-2bytes";
  const ciphertext = await encryptText(key, plaintext, contextId);
  assert.strictEqual(
    ciphertext.length,
    2 + MAC_OVERHEAD,
    "CRYPTO-6: 2-byte plaintext → 19-byte v2 ciphertext"
  );
  const decrypted = await decryptText(key, ciphertext, contextId);
  assert.strictEqual(decrypted, plaintext);
  console.log("  ✅ CRYPTO-6 short plaintext roundtrip");
}

async function testTagTamperThrows() {
  const key = await deriveKey(password, userId);
  const plaintext = "tamper-me";
  const contextId = "ctx-tamper";
  const ciphertext = await encryptText(key, plaintext, contextId);
  // Flip a byte in the AES-CTR ciphertext region (after version + tag).
  const tampered = ciphertext.slice();
  tampered[tampered.length - 1] ^= 0xff;
  await assert.rejects(
    () => decryptText(key, tampered, contextId),
    (err: unknown) => err instanceof E2EAuthError,
    "CRYPTO-7: Tampered ciphertext must throw E2EAuthError"
  );
  console.log("  ✅ CRYPTO-7 tag tamper throws E2EAuthError");
}

async function testLegacyV1BackwardCompat() {
  const key = await deriveKey(password, userId);
  const plaintext = "ab"; // 2 bytes → stripped payload is < 17 bytes → always v1 path
  const contextId = "ctx-legacy";
  const v2 = await encryptText(key, plaintext, contextId);
  // Simulate a legacy v1 payload: strip version + tag, leaving raw CTR ciphertext.
  const legacy = v2.slice(MAC_OVERHEAD);
  assert.ok(legacy.length < 1 + 16, "legacy payload shorter than v2 header");
  const decrypted = await decryptText(key, legacy, contextId);
  assert.strictEqual(decrypted, plaintext, "CRYPTO-8: legacy v1 ciphertext still decrypts");
  console.log("  ✅ CRYPTO-8 legacy v1 backward compatibility");
}

async function testBytesRoundtrip() {
  const key = await deriveKey(password, userId);
  const raw = new Uint8Array([0x00, 0x01, 0xff, 0xfe]);
  const contextId = "bytes-1";
  const ct = await encryptBytes(key, raw, contextId);
  assert.strictEqual(ct.length, raw.length + MAC_OVERHEAD, "v2 bytes = raw + 17");
  assert.strictEqual(ct[0], 0x02, "v2 bytes leading version byte");
  const dec = await decryptBytes(key, ct, contextId);
  assert.strictEqual(dec.length, raw.length);
  for (let i = 0; i < raw.length; i++) assert.strictEqual(dec[i], raw[i]);
  console.log("  ✅ encryptBytes/decryptBytes roundtrip (v2)");
}

async function run() {
  console.log("E2E Crypto test suite\n");
  await testKeyDerivation();
  await testRoundtrip();
  await testCiphertextFormatAndLength();
  await testWrongKeyOrContextIdThrows();
  await testDeterministicSameContextId();
  await testShortPlaintext();
  await testTagTamperThrows();
  await testLegacyV1BackwardCompat();
  await testBytesRoundtrip();
  console.log("\n🎉 All E2E crypto tests passed.");
}

run().catch((err) => {
  console.error("❌ Test failed:", err);
  process.exit(1);
});
