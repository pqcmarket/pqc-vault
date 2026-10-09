/** Decoders for the program's two account layouts. */
import { PublicKey } from "@solana/web3.js";
import { BUFFER_LEN, N, PAYLOAD_LEN, PROGRAM_ID, TOMBSTONE_LEN } from "./constants.js";

export interface Tombstone {
  version: number;
  bump: number;
  pkHash: Uint8Array;
  nextVault: PublicKey;
}

export interface SigBuffer {
  payer: PublicKey;
  vault: PublicKey;
  digest: Uint8Array;
  payload: Uint8Array;
}

export interface AccountLike {
  owner: PublicKey;
  data: Uint8Array;
  lamports: number | bigint;
}

/** A spent vault, or null if the account is not a tombstone. */
export function decodeTombstone(account: AccountLike | null, programId: PublicKey = PROGRAM_ID): Tombstone | null {
  if (!account || !account.owner.equals(programId)) return null;
  const d = account.data;
  if (d.length !== TOMBSTONE_LEN || d[0] !== 2) return null;
  return {
    version: d[1] as number,
    bump: d[2] as number,
    pkHash: d.slice(3, 3 + N),
    nextVault: new PublicKey(d.slice(35, 67)),
  };
}

export function decodeSigBuffer(account: AccountLike | null, programId: PublicKey = PROGRAM_ID): SigBuffer | null {
  if (!account || !account.owner.equals(programId)) return null;
  const d = account.data;
  if (d.length !== BUFFER_LEN || d[0] !== 1) return null;
  return {
    payer: new PublicKey(d.slice(1, 33)),
    vault: new PublicKey(d.slice(33, 65)),
    digest: d.slice(65, 97),
    payload: d.slice(97, 97 + PAYLOAD_LEN),
  };
}

/**
 * True when the on-chain buffer holds exactly `payload`. Check this before
 * sending Withdraw: with a load-balanced RPC the node that simulates the
 * withdraw may lag behind the one that confirmed the last write, and a partial
 * buffer fails as InvalidSignature.
 */
export function stagedPayloadMatches(account: AccountLike | null, payload: Uint8Array, programId: PublicKey = PROGRAM_ID): boolean {
  const buf = decodeSigBuffer(account, programId);
  if (!buf || buf.payload.length !== payload.length) return false;
  for (let i = 0; i < payload.length; i++) if (buf.payload[i] !== payload[i]) return false;
  return true;
}

export type VaultState =
  | { kind: "unspent"; lamports: bigint }
  | { kind: "spent"; tombstone: Tombstone; lamports: bigint };

/** What a vault address currently is. A missing account is an empty unspent vault. */
export function vaultState(account: AccountLike | null, programId: PublicKey = PROGRAM_ID): VaultState {
  const lamports = BigInt(account?.lamports ?? 0);
  const tombstone = decodeTombstone(account, programId);
  if (tombstone) return { kind: "spent", tombstone, lamports };
  return { kind: "unspent", lamports };
}
