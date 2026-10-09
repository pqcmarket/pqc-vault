/**
 * Transaction-level builders. Nothing here touches the network: the caller
 * supplies blockhashes, signs with the fee payer, and sends.
 */
import { PublicKey, Transaction, TransactionInstruction } from "@solana/web3.js";
import { DEFAULT_CHUNK, PAYLOAD_LEN, WITHDRAW_SOL_CU, WITHDRAW_TOKEN_CU } from "./constants.js";
import {
  closeBufferIx,
  depositSolIx,
  depositTokenIxs,
  setComputeUnitLimitIx,
  sweepSolIx,
  sweepTokenIx,
  TokenSpend,
  withdrawIx,
  writeSignatureIx,
} from "./instructions.js";
import { bufferAddress, VaultKey, vaultAddress } from "./vault.js";

export interface SpendRequest {
  /** The vault to spend. */
  from: VaultKey;
  /** `pkHash` of the vault the remainder rolls into (usually index + 1). */
  nextVaultHash: Uint8Array;
  recipient: PublicKey;
  amount: bigint;
  token?: TokenSpend | null;
  /** Fee payer for every transaction; also funds and gets back the buffer rent. */
  payer: PublicKey;
  chunkSize?: number;
  computeUnits?: number;
}

export interface SpendPlan {
  digest: Uint8Array;
  payload: Uint8Array;
  buffer: PublicKey;
  nextVault: PublicKey;
  /** Independent of each other; send in parallel, confirm all before withdrawing. */
  writeInstructions: TransactionInstruction[][];
  /** The spend itself. */
  withdrawInstructions: TransactionInstruction[];
  /**
   * Optional, after the withdraw confirms: closes the emptied vault token
   * account to the next vault. Empty for SOL spends.
   */
  cleanupInstructions: TransactionInstruction[];
  /** If a write landed but you abandon the spend: reclaims the buffer rent. */
  abortInstructions: TransactionInstruction[];
}

/**
 * Signs the spend with the vault's WOTS key and lays out every instruction.
 * This is the single point where the one-time key signs. Call it once per
 * vault; reuse the returned plan for retries.
 */
export function planSpend(req: SpendRequest): SpendPlan {
  const chunkSize = req.chunkSize ?? DEFAULT_CHUNK;
  if (chunkSize <= 0 || chunkSize > PAYLOAD_LEN) throw new RangeError("bad chunk size");
  const programId = req.from.programId;
  const token = req.token ?? null;
  const [nextVault] = vaultAddress(req.nextVaultHash, programId);
  const { digest, payload } = req.from.signSpend({
    recipient: req.recipient,
    mint: token?.mint ?? null,
    amount: req.amount,
    nextVaultHash: req.nextVaultHash,
  });
  const vault = req.from.address;
  const [buffer] = bufferAddress(vault, digest, req.payer, programId);

  const writeInstructions: TransactionInstruction[][] = [];
  for (let offset = 0; offset < payload.length; offset += chunkSize) {
    writeInstructions.push([
      writeSignatureIx({
        payer: req.payer,
        vault,
        digest,
        offset,
        chunk: payload.subarray(offset, Math.min(offset + chunkSize, payload.length)),
        programId,
      }),
    ]);
  }

  const withdrawInstructions = [
    setComputeUnitLimitIx(req.computeUnits ?? (token ? WITHDRAW_TOKEN_CU : WITHDRAW_SOL_CU)),
    withdrawIx({
      payer: req.payer,
      bufferPayer: req.payer,
      vault,
      nextVault,
      nextVaultHash: req.nextVaultHash,
      recipient: req.recipient,
      amount: req.amount,
      digest,
      token,
      programId,
    }),
  ];

  const cleanupInstructions = token
    ? [sweepTokenIx({ payer: req.payer, vault, nextVault, token, closeAta: true, programId })]
    : [];

  return {
    digest,
    payload,
    buffer,
    nextVault,
    writeInstructions,
    withdrawInstructions,
    cleanupInstructions,
    abortInstructions: [closeBufferIx({ payer: req.payer, buffer, programId })],
  };
}

function legacyTransaction(feePayer: PublicKey, recentBlockhash: string, ixs: TransactionInstruction[]): Transaction {
  const tx = new Transaction();
  tx.feePayer = feePayer;
  tx.recentBlockhash = recentBlockhash;
  tx.add(...ixs);
  return tx;
}

export interface BuiltSpend {
  plan: SpendPlan;
  writeTransactions: Transaction[];
  withdrawTransaction: Transaction;
  cleanupTransaction: Transaction | null;
}

/** `planSpend` wrapped into legacy `Transaction`s ready for the fee payer to sign. */
export function buildWithdrawTransactions(req: SpendRequest, recentBlockhash: string): BuiltSpend {
  const plan = planSpend(req);
  const wrap = (ixs: TransactionInstruction[]) => legacyTransaction(req.payer, recentBlockhash, ixs);
  return {
    plan,
    writeTransactions: plan.writeInstructions.map(wrap),
    withdrawTransaction: wrap(plan.withdrawInstructions),
    cleanupTransaction: plan.cleanupInstructions.length ? wrap(plan.cleanupInstructions) : null,
  };
}

export function buildDepositSolTransaction(
  p: { from: PublicKey; vault: PublicKey; lamports: bigint },
  recentBlockhash: string,
): Transaction {
  return legacyTransaction(p.from, recentBlockhash, [depositSolIx(p)]);
}

export function buildDepositTokenTransaction(
  p: Parameters<typeof depositTokenIxs>[0],
  recentBlockhash: string,
): Transaction {
  return legacyTransaction(p.depositor, recentBlockhash, depositTokenIxs(p));
}

/** Sweeps SOL and the given mints from a spent vault to its recorded next vault. */
export function buildSweepInstructions(p: {
  payer: PublicKey;
  vault: PublicKey;
  nextVault: PublicKey;
  tokens?: TokenSpend[];
  programId?: PublicKey;
}): TransactionInstruction[] {
  const base = p.programId ? { programId: p.programId } : {};
  return [
    sweepSolIx({ vault: p.vault, nextVault: p.nextVault, ...base }),
    ...(p.tokens ?? []).map((token) =>
      sweepTokenIx({ payer: p.payer, vault: p.vault, nextVault: p.nextVault, token, closeAta: true, ...base }),
    ),
  ];
}
