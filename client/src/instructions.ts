/** Raw instruction builders. One function per program instruction, plus the
 * token/system instructions a deposit needs, all hand-encoded. */
import { AccountMeta, PublicKey, SystemProgram, TransactionInstruction } from "@solana/web3.js";
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  COMPUTE_BUDGET_PROGRAM_ID,
  IX_CLOSE_BUFFER,
  IX_SWEEP,
  IX_WITHDRAW,
  IX_WRITE_SIGNATURE,
  KIND_SOL,
  KIND_TOKEN,
  PAYLOAD_LEN,
  PROGRAM_ID,
  SYSTEM_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
} from "./constants.js";
import { assertLen, concatBytes, u16le, u64le } from "./bytes.js";
import { bufferAddress } from "./vault.js";

export function associatedTokenAddress(owner: PublicKey, mint: PublicKey, tokenProgram: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [owner.toBytes(), tokenProgram.toBytes(), mint.toBytes()],
    ASSOCIATED_TOKEN_PROGRAM_ID,
  )[0];
}

export function isTokenProgram(key: PublicKey): boolean {
  return key.equals(TOKEN_PROGRAM_ID) || key.equals(TOKEN_2022_PROGRAM_ID);
}

export interface TokenSpend {
  mint: PublicKey;
  /** The mint's owner: TOKEN_PROGRAM_ID or TOKEN_2022_PROGRAM_ID. */
  tokenProgram: PublicKey;
  /**
   * Extra accounts a Token-2022 transfer hook needs, forwarded verbatim to
   * both transfers. Resolve them off-chain (e.g. spl-token's
   * `addExtraAccountMetasForExecute`) for the vault → recipient transfer; the
   * same list is reused for the vault → next-vault transfer.
   */
  extraAccounts?: AccountMeta[];
}

export function writeSignatureIx(p: {
  payer: PublicKey;
  vault: PublicKey;
  digest: Uint8Array;
  offset: number;
  chunk: Uint8Array;
  programId?: PublicKey;
}): TransactionInstruction {
  if (p.offset + p.chunk.length > PAYLOAD_LEN) throw new RangeError("chunk exceeds payload");
  const programId = p.programId ?? PROGRAM_ID;
  const [buffer] = bufferAddress(p.vault, p.digest, p.payer, programId);
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: p.payer, isSigner: true, isWritable: true },
      { pubkey: buffer, isSigner: false, isWritable: true },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(
      concatBytes(Uint8Array.of(IX_WRITE_SIGNATURE), p.vault.toBytes(), p.digest, u16le(p.offset), p.chunk),
    ),
  });
}

export function closeBufferIx(p: { payer: PublicKey; buffer: PublicKey; programId?: PublicKey }): TransactionInstruction {
  return new TransactionInstruction({
    programId: p.programId ?? PROGRAM_ID,
    keys: [
      { pubkey: p.payer, isSigner: true, isWritable: true },
      { pubkey: p.buffer, isSigner: false, isWritable: true },
    ],
    data: Buffer.from([IX_CLOSE_BUFFER]),
  });
}

export function withdrawIx(p: {
  /** Fee payer of this transaction; funds ATA creation / tombstone top-up. */
  payer: PublicKey;
  /** Who staged the signature; gets the buffer rent back. */
  bufferPayer: PublicKey;
  vault: PublicKey;
  nextVault: PublicKey;
  nextVaultHash: Uint8Array;
  recipient: PublicKey;
  amount: bigint;
  digest: Uint8Array;
  token?: TokenSpend | null;
  programId?: PublicKey;
}): TransactionInstruction {
  assertLen(p.nextVaultHash, 32, "nextVaultHash");
  const programId = p.programId ?? PROGRAM_ID;
  const [buffer] = bufferAddress(p.vault, p.digest, p.bufferPayer, programId);
  const keys: AccountMeta[] = [
    { pubkey: p.payer, isSigner: true, isWritable: true },
    { pubkey: buffer, isSigner: false, isWritable: true },
    { pubkey: p.bufferPayer, isSigner: false, isWritable: true },
    { pubkey: p.vault, isSigner: false, isWritable: true },
    { pubkey: p.nextVault, isSigner: false, isWritable: true },
    { pubkey: p.recipient, isSigner: false, isWritable: true },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
  ];
  if (p.token) {
    const t = p.token;
    keys.push(
      { pubkey: t.mint, isSigner: false, isWritable: false },
      { pubkey: associatedTokenAddress(p.vault, t.mint, t.tokenProgram), isSigner: false, isWritable: true },
      { pubkey: associatedTokenAddress(p.recipient, t.mint, t.tokenProgram), isSigner: false, isWritable: true },
      { pubkey: associatedTokenAddress(p.nextVault, t.mint, t.tokenProgram), isSigner: false, isWritable: true },
      { pubkey: t.tokenProgram, isSigner: false, isWritable: false },
      { pubkey: ASSOCIATED_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      ...(t.extraAccounts ?? []),
    );
  }
  return new TransactionInstruction({
    programId,
    keys,
    data: Buffer.from(
      concatBytes(
        Uint8Array.of(IX_WITHDRAW, p.token ? KIND_TOKEN : KIND_SOL),
        u64le(p.amount),
        p.nextVaultHash,
      ),
    ),
  });
}

/** Forwards late SOL deposits from a spent vault to its recorded next vault. */
export function sweepSolIx(p: { vault: PublicKey; nextVault: PublicKey; programId?: PublicKey }): TransactionInstruction {
  return new TransactionInstruction({
    programId: p.programId ?? PROGRAM_ID,
    keys: [
      { pubkey: p.vault, isSigner: false, isWritable: true },
      { pubkey: p.nextVault, isSigner: false, isWritable: true },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: Buffer.from([IX_SWEEP, KIND_SOL, 0]),
  });
}

/**
 * Forwards a spent vault's balance of `mint` to its recorded next vault and,
 * with `closeAta`, closes the emptied vault token account (rent to next vault).
 */
export function sweepTokenIx(p: {
  payer: PublicKey;
  vault: PublicKey;
  nextVault: PublicKey;
  token: TokenSpend;
  closeAta: boolean;
  programId?: PublicKey;
}): TransactionInstruction {
  const t = p.token;
  return new TransactionInstruction({
    programId: p.programId ?? PROGRAM_ID,
    keys: [
      { pubkey: p.vault, isSigner: false, isWritable: true },
      { pubkey: p.nextVault, isSigner: false, isWritable: true },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: p.payer, isSigner: true, isWritable: true },
      { pubkey: t.mint, isSigner: false, isWritable: false },
      { pubkey: associatedTokenAddress(p.vault, t.mint, t.tokenProgram), isSigner: false, isWritable: true },
      { pubkey: associatedTokenAddress(p.nextVault, t.mint, t.tokenProgram), isSigner: false, isWritable: true },
      { pubkey: t.tokenProgram, isSigner: false, isWritable: false },
      { pubkey: ASSOCIATED_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      ...(t.extraAccounts ?? []),
    ],
    data: Buffer.from([IX_SWEEP, KIND_TOKEN, p.closeAta ? 1 : 0]),
  });
}

// ----- deposits and helpers -----

export function depositSolIx(p: { from: PublicKey; vault: PublicKey; lamports: bigint }): TransactionInstruction {
  return SystemProgram.transfer({ fromPubkey: p.from, toPubkey: p.vault, lamports: p.lamports });
}

/** `CreateIdempotent` on the Associated Token Account program. */
export function createAtaIdempotentIx(p: {
  payer: PublicKey;
  owner: PublicKey;
  mint: PublicKey;
  tokenProgram: PublicKey;
}): TransactionInstruction {
  return new TransactionInstruction({
    programId: ASSOCIATED_TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: p.payer, isSigner: true, isWritable: true },
      { pubkey: associatedTokenAddress(p.owner, p.mint, p.tokenProgram), isSigner: false, isWritable: true },
      { pubkey: p.owner, isSigner: false, isWritable: false },
      { pubkey: p.mint, isSigner: false, isWritable: false },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: p.tokenProgram, isSigner: false, isWritable: false },
    ],
    data: Buffer.from([1]),
  });
}

/** `TransferChecked` from the depositor's ATA to the vault's ATA. */
export function transferCheckedIx(p: {
  source: PublicKey;
  mint: PublicKey;
  destination: PublicKey;
  owner: PublicKey;
  amount: bigint;
  decimals: number;
  tokenProgram: PublicKey;
  extraAccounts?: AccountMeta[];
}): TransactionInstruction {
  return new TransactionInstruction({
    programId: p.tokenProgram,
    keys: [
      { pubkey: p.source, isSigner: false, isWritable: true },
      { pubkey: p.mint, isSigner: false, isWritable: false },
      { pubkey: p.destination, isSigner: false, isWritable: true },
      { pubkey: p.owner, isSigner: true, isWritable: false },
      ...(p.extraAccounts ?? []),
    ],
    data: Buffer.from(concatBytes(Uint8Array.of(12), u64le(p.amount), Uint8Array.of(p.decimals))),
  });
}

/** Deposit tokens: create the vault's ATA if needed, then transfer. */
export function depositTokenIxs(p: {
  depositor: PublicKey;
  vault: PublicKey;
  mint: PublicKey;
  tokenProgram: PublicKey;
  amount: bigint;
  decimals: number;
  extraAccounts?: AccountMeta[];
}): TransactionInstruction[] {
  const createIx = createAtaIdempotentIx({ payer: p.depositor, owner: p.vault, mint: p.mint, tokenProgram: p.tokenProgram });
  const transferArgs = {
    source: associatedTokenAddress(p.depositor, p.mint, p.tokenProgram),
    mint: p.mint,
    destination: associatedTokenAddress(p.vault, p.mint, p.tokenProgram),
    owner: p.depositor,
    amount: p.amount,
    decimals: p.decimals,
    tokenProgram: p.tokenProgram,
  };
  return [
    createIx,
    transferCheckedIx(p.extraAccounts ? { ...transferArgs, extraAccounts: p.extraAccounts } : transferArgs),
  ];
}

export function setComputeUnitLimitIx(units: number): TransactionInstruction {
  const data = new Uint8Array(5);
  data[0] = 2;
  new DataView(data.buffer).setUint32(1, units, true);
  return new TransactionInstruction({ programId: COMPUTE_BUDGET_PROGRAM_ID, keys: [], data: Buffer.from(data) });
}
