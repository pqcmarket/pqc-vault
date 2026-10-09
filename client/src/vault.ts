/**
 * Vault keys and addresses. Seeds are derived from the identity with
 * HKDF-SHA256 and never leave the caller.
 */
import { PublicKey } from "@solana/web3.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  N,
  PROGRAM_ID,
  SIG_SEED,
  SOL_MINT,
  SPEND_DOMAIN,
  VAULT_PUB_INFO,
  VAULT_SEED,
  VAULT_SK_INFO,
  VAULT_VERSION,
} from "./constants.js";
import { assertLen, concatBytes, u32be, u64le, utf8ToBytes } from "./bytes.js";
import { publicKey, publicKeyHash, sign } from "./wots.js";

/** The post-quantum identity the web app derives from a wallet signature. */
export interface Identity {
  skSeed: Uint8Array;
  pubSeed: Uint8Array;
}

export interface VaultSeeds {
  skSeed: Uint8Array;
  pubSeed: Uint8Array;
}

/**
 * Per-vault seeds:
 *   skSeed_i  = HKDF-SHA256(ikm = identity.skSeed,  salt = ∅, info = "pqc.market/vault/v1/sk"  ‖ u32be(i), 32)
 *   pubSeed_i = HKDF-SHA256(ikm = identity.pubSeed, salt = ∅, info = "pqc.market/vault/v1/pub" ‖ u32be(i), 32)
 */
export function deriveVaultSeeds(identity: Identity, index: number): VaultSeeds {
  assertLen(identity.skSeed, N, "identity.skSeed");
  assertLen(identity.pubSeed, N, "identity.pubSeed");
  const idx = u32be(index);
  return {
    skSeed: hkdf(sha256, identity.skSeed, undefined, concatBytes(utf8ToBytes(VAULT_SK_INFO), idx), N),
    pubSeed: hkdf(sha256, identity.pubSeed, undefined, concatBytes(utf8ToBytes(VAULT_PUB_INFO), idx), N),
  };
}

/** `["vault", version, pkHash]` under the program. */
export function vaultAddress(pkHash: Uint8Array, programId: PublicKey = PROGRAM_ID): [PublicKey, number] {
  assertLen(pkHash, N, "pkHash");
  return PublicKey.findProgramAddressSync([VAULT_SEED, Uint8Array.of(VAULT_VERSION), pkHash], programId);
}

/** `["sig", vault, digest, payer]`: where a payer stages a signature. */
export function bufferAddress(
  vault: PublicKey,
  digest: Uint8Array,
  payer: PublicKey,
  programId: PublicKey = PROGRAM_ID,
): [PublicKey, number] {
  assertLen(digest, N, "digest");
  return PublicKey.findProgramAddressSync([SIG_SEED, vault.toBytes(), digest, payer.toBytes()], programId);
}

export interface SpendParams {
  /** The vault being spent. */
  vault: PublicKey;
  /** Wallet that receives `amount` (its ATA for token spends). */
  recipient: PublicKey;
  /** Mint, or omit/null for SOL. */
  mint?: PublicKey | null;
  /** Lamports or base token units. */
  amount: bigint;
  /** `pkHash` of the vault the remainder rolls into. */
  nextVaultHash: Uint8Array;
  programId?: PublicKey;
}

/** `SHA-256(domain ‖ program_id ‖ vault ‖ recipient ‖ mint-or-SOL ‖ amount_le ‖ next_vault_hash)`. */
export function spendDigest(p: SpendParams): Uint8Array {
  assertLen(p.nextVaultHash, N, "nextVaultHash");
  const mint = p.mint ?? SOL_MINT;
  return sha256(
    concatBytes(
      SPEND_DOMAIN,
      (p.programId ?? PROGRAM_ID).toBytes(),
      p.vault.toBytes(),
      p.recipient.toBytes(),
      mint.toBytes(),
      u64le(p.amount),
      p.nextVaultHash,
    ),
  );
}

/**
 * One vault's key material and address. Holds the secret seed: keep it in the
 * caller's memory only.
 */
export class VaultKey {
  readonly pkHash: Uint8Array;
  readonly address: PublicKey;
  readonly bump: number;

  constructor(
    readonly skSeed: Uint8Array,
    readonly pubSeed: Uint8Array,
    readonly programId: PublicKey = PROGRAM_ID,
  ) {
    this.pkHash = publicKeyHash(publicKey(skSeed, pubSeed));
    [this.address, this.bump] = vaultAddress(this.pkHash, programId);
  }

  static fromIdentity(identity: Identity, index: number, programId: PublicKey = PROGRAM_ID): VaultKey {
    const seeds = deriveVaultSeeds(identity, index);
    return new VaultKey(seeds.skSeed, seeds.pubSeed, programId);
  }

  /**
   * Signs a spend of this vault. Returns the digest and the 2,176-byte payload
   * (`pubSeed ‖ signature`) to stage on-chain.
   *
   * Sign once per vault. If the spend fails for an environmental reason,
   * resubmit this same payload with the same parameters; never sign a second,
   * different message with the same vault key.
   */
  signSpend(params: Omit<SpendParams, "vault" | "programId">): { digest: Uint8Array; payload: Uint8Array } {
    const digest = spendDigest({ ...params, vault: this.address, programId: this.programId });
    const payload = concatBytes(this.pubSeed, sign(this.skSeed, this.pubSeed, digest));
    return { digest, payload };
  }
}
