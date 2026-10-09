import { test } from "node:test";
import assert from "node:assert/strict";
import { Keypair, PublicKey } from "@solana/web3.js";
import { bufferAddress, deriveVaultSeeds, spendDigest, VaultKey, vaultAddress } from "./vault.js";
import { planSpend } from "./transactions.js";
import { decodeTombstone, vaultState } from "./state.js";
import { BUFFER_LEN, PAYLOAD_LEN, PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOMBSTONE_LEN } from "./constants.js";
import { bytesToHex } from "./bytes.js";

const identity = { skSeed: new Uint8Array(32).fill(1), pubSeed: new Uint8Array(32).fill(2) };

test("vault seeds are per index and deterministic", () => {
  const a = deriveVaultSeeds(identity, 0);
  const b = deriveVaultSeeds(identity, 1);
  assert.deepEqual(a, deriveVaultSeeds(identity, 0));
  assert.notDeepEqual(a.skSeed, b.skSeed);
  assert.notDeepEqual(a.pubSeed, b.pubSeed);
  assert.notDeepEqual(a.skSeed, a.pubSeed);
});

test("vault address is the PDA of the key hash", () => {
  const v = VaultKey.fromIdentity(identity, 0);
  const [addr, bump] = vaultAddress(v.pkHash);
  assert.ok(v.address.equals(addr));
  assert.equal(v.bump, bump);
  assert.ok(PublicKey.isOnCurve(addr.toBytes()) === false);
});

test("planSpend produces three writes plus a withdraw bound to the digest", () => {
  const v0 = VaultKey.fromIdentity(identity, 0);
  const v1 = VaultKey.fromIdentity(identity, 1);
  const payer = Keypair.generate().publicKey;
  const recipient = Keypair.generate().publicKey;
  const plan = planSpend({ from: v0, nextVaultHash: v1.pkHash, recipient, amount: 1_000_000n, payer });
  assert.equal(plan.payload.length, PAYLOAD_LEN);
  assert.equal(plan.writeInstructions.length, 3);
  assert.ok(plan.nextVault.equals(v1.address));
  assert.ok(plan.buffer.equals(bufferAddress(v0.address, plan.digest, payer)[0]));
  const expected = spendDigest({ vault: v0.address, recipient, amount: 1_000_000n, nextVaultHash: v1.pkHash });
  assert.equal(bytesToHex(plan.digest), bytesToHex(expected));
  // Every write transaction fits under the packet limit with margin.
  for (const [ix] of plan.writeInstructions) {
    assert.ok(ix!.data.length <= 850 + 67);
  }
  assert.equal(plan.cleanupInstructions.length, 0);
  const tokenPlan = planSpend({
    from: v0,
    nextVaultHash: v1.pkHash,
    recipient,
    amount: 5n,
    payer,
    token: { mint: Keypair.generate().publicKey, tokenProgram: TOKEN_2022_PROGRAM_ID },
  });
  assert.equal(tokenPlan.withdrawInstructions[1]!.keys.length, 13);
  assert.equal(tokenPlan.cleanupInstructions.length, 1);
  assert.notEqual(bytesToHex(tokenPlan.digest), bytesToHex(plan.digest));
});

test("state decoders", () => {
  const next = Keypair.generate().publicKey;
  const data = new Uint8Array(TOMBSTONE_LEN);
  data[0] = 2;
  data[1] = 1;
  data[2] = 254;
  data.set(new Uint8Array(32).fill(0xab), 3);
  data.set(next.toBytes(), 35);
  const t = decodeTombstone({ owner: PROGRAM_ID, data, lamports: 1 });
  assert.ok(t);
  assert.ok(t.nextVault.equals(next));
  assert.equal(t.bump, 254);
  assert.equal(vaultState(null).kind, "unspent");
  assert.equal(vaultState({ owner: PROGRAM_ID, data, lamports: 5 }).kind, "spent");
  assert.equal(decodeTombstone({ owner: Keypair.generate().publicKey, data, lamports: 1 }), null);
  assert.equal(BUFFER_LEN, 2273);
});
