/**
 * Winternitz one-time signatures, w = 16, over SHA-256. Byte-for-byte the
 * construction the on-chain verifier implements (programs/pqc-vault/src/wots.rs).
 *
 * - ADRS: 32 bytes, big-endian u32 `type | a | b | c` at 0, 4, 8, 12, then zeros.
 *   type 0 = chain step, 3 = secret PRF.
 * - F(pubSeed, ADRS, x) = SHA-256(pubSeed ‖ ADRS ‖ x)
 * - sk_i = SHA-256(skSeed ‖ ADRS(3, leaf, i, 0))
 * - step at position s: x ← F(pubSeed, ADRS(0, leaf, i, s), x)
 * - pk_i = sk_i walked 15 steps; σ_i = sk_i walked d_i steps.
 * - public key = pubSeed ‖ pk_0 ‖ … ‖ pk_66; the vault commits to SHA-256 of it.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { N, PAYLOAD_LEN, SIGNATURE_LEN, WOTS_LEN } from "./constants.js";
import { assertLen, concatBytes, equalBytes, u32be } from "./bytes.js";

export const ADRS_TYPE_CHAIN = 0;
export const ADRS_TYPE_SECRET = 3;
/** Vault keys are standalone (seeds are already per-vault), so the leaf is 0. */
export const LEAF = 0;
export const W_MAX = 15;
export const LEN1 = 64;

export function adrs(type: number, a: number, b: number, c: number): Uint8Array {
  return concatBytes(u32be(type), u32be(a), u32be(b), u32be(c), new Uint8Array(16));
}

/** Tweakable hash. */
export function F(pubSeed: Uint8Array, address: Uint8Array, x: Uint8Array): Uint8Array {
  return sha256(concatBytes(pubSeed, address, x));
}

/** 64 digest nibbles (high then low per byte) followed by 3 checksum nibbles. */
export function digestToSteps(digest: Uint8Array): Uint8Array {
  assertLen(digest, N, "digest");
  const steps = new Uint8Array(WOTS_LEN);
  let checksum = 0;
  for (let j = 0; j < N; j++) {
    const byte = digest[j] as number;
    const hi = byte >> 4;
    const lo = byte & 15;
    steps[2 * j] = hi;
    steps[2 * j + 1] = lo;
    checksum += W_MAX - hi + (W_MAX - lo);
  }
  steps[LEN1] = (checksum >> 8) & 15;
  steps[LEN1 + 1] = (checksum >> 4) & 15;
  steps[LEN1 + 2] = checksum & 15;
  return steps;
}

/** Chain steps a verifier walks for `digest`: 45 (best) to 990 (worst). */
export function verifySteps(digest: Uint8Array): number {
  let total = 0;
  for (const d of digestToSteps(digest)) total += W_MAX - d;
  return total;
}

/** Walks `x` through positions [from, to). */
export function chain(pubSeed: Uint8Array, index: number, x: Uint8Array, from: number, to: number): Uint8Array {
  let value = x;
  for (let s = from; s < to; s++) {
    value = F(pubSeed, adrs(ADRS_TYPE_CHAIN, LEAF, index, s), value);
  }
  return value;
}

export function secretElement(skSeed: Uint8Array, index: number): Uint8Array {
  assertLen(skSeed, N, "skSeed");
  return sha256(concatBytes(skSeed, adrs(ADRS_TYPE_SECRET, LEAF, index, 0)));
}

/** `pubSeed ‖ pk_0 ‖ … ‖ pk_66` (2,176 bytes). */
export function publicKey(skSeed: Uint8Array, pubSeed: Uint8Array): Uint8Array {
  assertLen(pubSeed, N, "pubSeed");
  const out = new Uint8Array(PAYLOAD_LEN);
  out.set(pubSeed, 0);
  for (let i = 0; i < WOTS_LEN; i++) {
    out.set(chain(pubSeed, i, secretElement(skSeed, i), 0, W_MAX), N + i * N);
  }
  return out;
}

/** What a vault address commits to. */
export function publicKeyHash(pk: Uint8Array): Uint8Array {
  assertLen(pk, PAYLOAD_LEN, "public key");
  return sha256(pk);
}

/** Signs a 32-byte digest. One signature per key, ever. */
export function sign(skSeed: Uint8Array, pubSeed: Uint8Array, digest: Uint8Array): Uint8Array {
  assertLen(pubSeed, N, "pubSeed");
  const steps = digestToSteps(digest);
  const sig = new Uint8Array(SIGNATURE_LEN);
  for (let i = 0; i < WOTS_LEN; i++) {
    sig.set(chain(pubSeed, i, secretElement(skSeed, i), 0, steps[i] as number), i * N);
  }
  return sig;
}

/** Recovers `SHA-256(pubSeed ‖ pk)` from a signature, as the program does. */
export function recoverPublicKeyHash(pubSeed: Uint8Array, signature: Uint8Array, digest: Uint8Array): Uint8Array {
  assertLen(pubSeed, N, "pubSeed");
  assertLen(signature, SIGNATURE_LEN, "signature");
  const steps = digestToSteps(digest);
  const pk = new Uint8Array(PAYLOAD_LEN);
  pk.set(pubSeed, 0);
  for (let i = 0; i < WOTS_LEN; i++) {
    const sigma = signature.subarray(i * N, (i + 1) * N);
    pk.set(chain(pubSeed, i, sigma, steps[i] as number, W_MAX), N + i * N);
  }
  return sha256(pk);
}

export function verify(pkHash: Uint8Array, pubSeed: Uint8Array, signature: Uint8Array, digest: Uint8Array): boolean {
  return equalBytes(recoverPublicKeyHash(pubSeed, signature, digest), pkHash);
}
