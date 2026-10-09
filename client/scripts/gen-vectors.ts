/**
 * Writes the shared test vectors to ../vectors/. The Rust crate's tests read
 * the same files, so both implementations are pinned to identical bytes.
 */
import { writeFileSync } from "node:fs";
import { Keypair, PublicKey } from "@solana/web3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "../src/bytes.js";
import {
  PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  VAULT_PUB_INFO,
  VAULT_SK_INFO,
  VAULT_VERSION,
  SPEND_DOMAIN,
} from "../src/constants.js";
import { digestToSteps, publicKey, publicKeyHash, secretElement, sign, verifySteps } from "../src/wots.js";
import { bufferAddress, deriveVaultSeeds, spendDigest, VaultKey } from "../src/vault.js";

const hex = bytesToHex;
const fill = (b: number) => new Uint8Array(32).fill(b);
/** Deterministic pseudo-random bytes from a label. */
const prf = (label: string) => sha256(utf8ToBytes(`pqc-vault-vectors/${label}`));
const det = (label: string) => Keypair.fromSeed(prf(label)).publicKey;

function wotsCase(name: string, skSeed: Uint8Array, pubSeed: Uint8Array, digest: Uint8Array) {
  const pk = publicKey(skSeed, pubSeed);
  return {
    name,
    skSeed: hex(skSeed),
    pubSeed: hex(pubSeed),
    digest: hex(digest),
    steps: [...digestToSteps(digest)],
    verifySteps: verifySteps(digest),
    sk0: hex(secretElement(skSeed, 0)),
    sk66: hex(secretElement(skSeed, 66)),
    pk0: hex(pk.subarray(32, 64)),
    publicKey: hex(pk),
    publicKeyHash: hex(publicKeyHash(pk)),
    signature: hex(sign(skSeed, pubSeed, digest)),
  };
}

const wots = {
  description:
    "WOTS w=16 over SHA-256. ADRS = u32be(type)|u32be(leaf)|u32be(chain)|u32be(step)|16 zero bytes. " +
    "F(pubSeed, ADRS, x) = SHA-256(pubSeed||ADRS||x). sk_i = SHA-256(skSeed||ADRS(3,leaf,i,0)). " +
    "pk_i = sk_i walked 15 steps (positions 0..14). sigma_i = sk_i walked d_i steps. " +
    "publicKey = pubSeed||pk_0..pk_66; publicKeyHash = SHA-256(publicKey). leaf = 0 for vault keys.",
  params: { n: 32, w: 16, len1: 64, len2: 3, len: 67, leaf: 0, adrsTypeChain: 0, adrsTypeSecret: 3 },
  cases: [
    wotsCase("fixed-seeds", fill(7), fill(9), fill(0x5a)),
    wotsCase("all-zero-digest-worst-case", prf("sk/worst"), prf("pub/worst"), new Uint8Array(32)),
    wotsCase("all-ff-digest-best-case", prf("sk/best"), prf("pub/best"), new Uint8Array(32).fill(0xff)),
    wotsCase("random-1", prf("sk/1"), prf("pub/1"), prf("digest/1")),
    wotsCase("random-2", prf("sk/2"), prf("pub/2"), prf("digest/2")),
  ],
};
writeFileSync(new URL("../../vectors/wots.json", import.meta.url), JSON.stringify(wots, null, 2) + "\n");

const identity = { skSeed: prf("identity/sk"), pubSeed: prf("identity/pub") };
const vaults = [0, 1, 2].map((index) => {
  const seeds = deriveVaultSeeds(identity, index);
  const key = new VaultKey(seeds.skSeed, seeds.pubSeed);
  return {
    index,
    skSeed: hex(seeds.skSeed),
    pubSeed: hex(seeds.pubSeed),
    pkHash: hex(key.pkHash),
    address: key.address.toBase58(),
    bump: key.bump,
  };
});
const v0 = VaultKey.fromIdentity(identity, 0);
const v1 = VaultKey.fromIdentity(identity, 1);
const payer = det("payer");
const recipient = det("recipient");
const mint = det("mint");

function spendCase(mintKey: PublicKey | null, amount: bigint) {
  const digest = spendDigest({ vault: v0.address, recipient, mint: mintKey, amount, nextVaultHash: v1.pkHash });
  const { payload } = v0.signSpend({ recipient, mint: mintKey, amount, nextVaultHash: v1.pkHash });
  return {
    vault: v0.address.toBase58(),
    recipient: recipient.toBase58(),
    mint: mintKey ? mintKey.toBase58() : null,
    tokenProgram: mintKey ? TOKEN_2022_PROGRAM_ID.toBase58() : null,
    amount: amount.toString(),
    nextVaultHash: hex(v1.pkHash),
    nextVault: v1.address.toBase58(),
    digest: hex(digest),
    verifySteps: verifySteps(digest),
    bufferPayer: payer.toBase58(),
    buffer: bufferAddress(v0.address, digest, payer)[0].toBase58(),
    payload: hex(payload),
  };
}

const vault = {
  description:
    "Identity -> per-vault seeds (HKDF-SHA256, salt empty, info = prefix || u32be(index)) -> WOTS key -> " +
    "vault PDA ['vault', version, pkHash]. Spend digest = SHA-256(domain||programId||vault||recipient||mint-or-zeros||amount_le64||nextVaultHash). " +
    "Buffer PDA ['sig', vault, digest, payer]. payload = pubSeed||signature.",
  programId: PROGRAM_ID.toBase58(),
  vaultVersion: VAULT_VERSION,
  spendDomain: new TextDecoder().decode(SPEND_DOMAIN),
  hkdf: { skInfoPrefix: VAULT_SK_INFO, pubInfoPrefix: VAULT_PUB_INFO, salt: "", length: 32 },
  identity: { skSeed: hex(identity.skSeed), pubSeed: hex(identity.pubSeed) },
  vaults,
  solSpend: spendCase(null, 1_000_000n),
  tokenSpend: spendCase(mint, 123_456_789n),
};
writeFileSync(new URL("../../vectors/vault.json", import.meta.url), JSON.stringify(vault, null, 2) + "\n");
console.log("wrote vectors/wots.json and vectors/vault.json");
console.log("sanity:", hex(concatBytes(fill(1))).length === 64 ? "ok" : "bad");
