import { PublicKey } from "@solana/web3.js";

/** pqc-vault program id. Identical on devnet and mainnet. */
export const PROGRAM_ID = new PublicKey("DNsPfPecrbnS7jFqMpEDG3VoWAdkuaU2VxsmaPENcg9F");

export const VAULT_SEED = new TextEncoder().encode("vault");
export const VAULT_VERSION = 1;
export const SIG_SEED = new TextEncoder().encode("sig");
export const SPEND_DOMAIN = new TextEncoder().encode("pqc.market/vault-spend/v1");

/** HKDF info prefixes for per-vault seeds; the big-endian u32 vault index follows. */
export const VAULT_SK_INFO = "pqc.market/vault/v1/sk";
export const VAULT_PUB_INFO = "pqc.market/vault/v1/pub";

/** Stands in for the mint in a SOL spend. */
export const SOL_MINT = new PublicKey(new Uint8Array(32));

export const SYSTEM_PROGRAM_ID = new PublicKey(new Uint8Array(32));
export const TOKEN_PROGRAM_ID = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
export const TOKEN_2022_PROGRAM_ID = new PublicKey("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
export const ASSOCIATED_TOKEN_PROGRAM_ID = new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
export const COMPUTE_BUDGET_PROGRAM_ID = new PublicKey("ComputeBudget111111111111111111111111111111");

export const IX_WRITE_SIGNATURE = 0;
export const IX_WITHDRAW = 1;
export const IX_CLOSE_BUFFER = 2;
export const IX_SWEEP = 3;
export const KIND_SOL = 0;
export const KIND_TOKEN = 1;

/** WOTS sizes. */
export const N = 32;
export const WOTS_LEN = 67;
export const SIGNATURE_LEN = WOTS_LEN * N; // 2144
/** pubSeed ‖ signature: what gets staged on-chain. */
export const PAYLOAD_LEN = N + SIGNATURE_LEN; // 2176

/** Account sizes. */
export const BUFFER_LEN = 97 + PAYLOAD_LEN; // 2273
export const TOMBSTONE_LEN = 67;

/**
 * Bytes of payload per WriteSignature transaction. 2,176 bytes take three.
 * Leaves room for the fee payer's own priority-fee instructions.
 */
export const DEFAULT_CHUNK = 850;

/**
 * Compute budgets. Measured worst case (all-zero digest, 990 chain steps):
 * SOL spend 247k CU, Token-2022 spend 298k CU, both including a 45k CU margin
 * for an unlucky PDA bump search. See vectors/compute.json.
 */
export const WITHDRAW_SOL_CU = 300_000;
export const WITHDRAW_TOKEN_CU = 400_000;

export const ERRORS: Record<number, string> = {
  6000: "InvalidSignature: the WOTS signature does not recover this vault's key",
  6001: "VaultAlreadySpent: this vault spent once; its remainder is in next_vault",
  6002: "UnexpectedVaultState: the vault account is neither empty nor a tombstone",
  6003: "InvalidBuffer: signature buffer missing, foreign, or malformed",
  6004: "BufferDigestMismatch: the staged signature is for a different message",
  6005: "BufferVaultMismatch: the staged signature is for a different vault",
  6006: "BufferPayerMismatch: only the buffer's payer may write to or close it",
  6007: "WriteOutOfBounds: chunk falls outside the buffer payload",
  6008: "InvalidNextVault: next_vault is not the PDA of next_vault_hash or not an empty account",
  6009: "NextVaultIsSelf: a vault cannot roll into itself",
  6010: "NextVaultAlreadySpent: next_vault was already spent",
  6011: "RecipientIsVault: the recipient cannot be the vault being spent",
  6012: "InsufficientFunds: less than amount plus tombstone rent available",
  6013: "BelowRentExemption: a credited account would be left rent-paying",
  6014: "InvalidTokenProgram: not SPL Token / Token-2022, or not the mint's owner",
  6015: "InvalidMint: mint account malformed",
  6016: "InvalidTokenAccount: not the expected associated token account",
  6017: "InvalidAssociatedTokenProgram",
  6018: "InvalidSystemProgram",
  6019: "NotATombstone: sweep needs a spent vault",
  6020: "InvalidKind: kind must be 0 (SOL) or 1 (token)",
};
