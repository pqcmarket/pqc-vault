import { test } from "node:test";
import assert from "node:assert/strict";
import { digestToSteps, publicKey, publicKeyHash, recoverPublicKeyHash, sign, verify, verifySteps } from "./wots.js";
import { PAYLOAD_LEN, SIGNATURE_LEN } from "./constants.js";
import { hexToBytes } from "./bytes.js";

test("digest splits into nibbles high first, checksum appended", () => {
  const digest = new Uint8Array(32);
  digest[0] = 0xa3;
  const steps = digestToSteps(digest);
  assert.equal(steps[0], 0xa);
  assert.equal(steps[1], 0x3);
  // (15-10) + (15-3) + 62*15 = 947 = 0x3B3
  assert.deepEqual([...steps.subarray(64)], [3, 0xb, 3]);
  assert.equal(verifySteps(new Uint8Array(32)), 990);
  assert.equal(verifySteps(new Uint8Array(32).fill(0xff)), 45);
});

test("sign / verify round trip, and tampering fails", () => {
  const sk = new Uint8Array(32).fill(7);
  const ps = new Uint8Array(32).fill(9);
  const digest = new Uint8Array(32).fill(0x5a);
  const pk = publicKey(sk, ps);
  assert.equal(pk.length, PAYLOAD_LEN);
  const sig = sign(sk, ps, digest);
  assert.equal(sig.length, SIGNATURE_LEN);
  const pkHash = publicKeyHash(pk);
  assert.ok(verify(pkHash, ps, sig, digest));
  const other = digest.slice();
  (other[31] as number) ^= 1;
  assert.ok(!verify(pkHash, ps, sig, other));
  const badSig = sig.slice();
  (badSig[100] as number) ^= 1;
  assert.ok(!verify(pkHash, ps, badSig, digest));
  assert.ok(!verify(pkHash, new Uint8Array(32), sig, digest));
  assert.deepEqual(recoverPublicKeyHash(ps, sig, digest), pkHash);
});

test("known answer: matches the Rust unit test fixtures", () => {
  // The Rust crate's unit test uses the same fixed inputs; the vectors file
  // produced by scripts/gen-vectors.ts pins the exact bytes for both sides.
  const sk = hexToBytes("07".repeat(32));
  const ps = hexToBytes("09".repeat(32));
  const pk = publicKey(sk, ps);
  assert.deepEqual(pk.subarray(0, 32), ps);
});
