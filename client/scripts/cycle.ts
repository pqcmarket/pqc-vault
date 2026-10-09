/**
 * One full cycle on a live cluster: deposit → stage signature → withdraw →
 * remainder lands in the next vault. Prints every transaction signature and
 * writes a JSON record to ../runs/.
 *
 * Usage:
 *   tsx scripts/cycle.ts --rpc <url> --payer <keypair.json> [--cluster devnet|mainnet]
 *                        [--identity <32-byte hex>] [--index <n>]
 *                        [--deposit <lamports>] [--amount <lamports>] [--recipient <pubkey>]
 *
 * `--deposit 0` skips the deposit and spends what the vault already holds (use
 * it with the same --identity to resume a cycle whose withdraw did not land).
 *
 * The identity seed is a test identity; a fresh random one is generated and
 * printed when omitted. The payer is an ordinary ed25519 wallet: it funds the
 * deposit, pays fees, and gets the signature-buffer rent back.
 */
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { Connection, Keypair, PublicKey, Transaction, sendAndConfirmTransaction } from "@solana/web3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "../src/bytes.js";
import { PROGRAM_ID, TOMBSTONE_LEN, ERRORS } from "../src/constants.js";
import { VaultKey } from "../src/vault.js";
import { planSpend } from "../src/transactions.js";
import { depositSolIx } from "../src/instructions.js";
import { stagedPayloadMatches, vaultState } from "../src/state.js";

function arg(name: string, fallback?: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

const rpc = arg("rpc");
const payerPath = arg("payer");
if (!rpc || !payerPath) {
  console.error("usage: tsx scripts/cycle.ts --rpc <url> --payer <keypair.json> [--cluster devnet|mainnet] ...");
  process.exit(2);
}
const cluster = arg("cluster", rpc.includes("devnet") ? "devnet" : "mainnet")!;
const index = Number(arg("index", "0"));
const depositLamports = BigInt(arg("deposit", "10000000")!); // 0.01 SOL
const amount = BigInt(arg("amount", "4000000")!); // 0.004 SOL to the recipient

const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(payerPath, "utf8"))));
const recipient = arg("recipient") ? new PublicKey(arg("recipient")!) : payer.publicKey;
const identitySeed = arg("identity") ? hexToBytes(arg("identity")!) : randomBytes(32);
const identity = { skSeed: sha256(new Uint8Array([...identitySeed, 0])), pubSeed: sha256(new Uint8Array([...identitySeed, 1])) };

const connection = new Connection(rpc, "confirmed");
const explorer = (sig: string) =>
  `https://explorer.solana.com/tx/${sig}${cluster === "devnet" ? "?cluster=devnet" : ""}`;

function explain(err: unknown): string {
  const text = err instanceof Error ? err.message : String(err);
  const m = /custom program error: 0x([0-9a-f]+)/i.exec(text);
  if (m) {
    const code = parseInt(m[1]!, 16);
    return `${text}\n  → ${ERRORS[code] ?? `unknown custom error ${code}`}`;
  }
  return text;
}

async function send(label: string, ixs: Transaction["instructions"]): Promise<string> {
  const tx = new Transaction().add(...ixs);
  tx.feePayer = payer.publicKey;
  try {
    const sig = await sendAndConfirmTransaction(connection, tx, [payer], { commitment: "confirmed" });
    console.log(`  ${label}: ${sig}\n    ${explorer(sig)}`);
    return sig;
  } catch (err) {
    console.error(`  ${label} FAILED: ${explain(err)}`);
    throw err;
  }
}

async function main() {
  console.log(`cluster:    ${cluster}`);
  console.log(`program:    ${PROGRAM_ID.toBase58()}`);
  console.log(`payer:      ${payer.publicKey.toBase58()}`);
  console.log(`identity:   ${bytesToHex(identitySeed)}  (test identity seed; --identity to reuse)`);

  const program = await connection.getAccountInfo(PROGRAM_ID);
  if (!program?.executable) throw new Error(`program ${PROGRAM_ID.toBase58()} is not deployed on ${cluster}`);

  const v0 = VaultKey.fromIdentity(identity, index);
  const v1 = VaultKey.fromIdentity(identity, index + 1);
  console.log(`vault[${index}]:   ${v0.address.toBase58()}`);
  console.log(`vault[${index + 1}]:   ${v1.address.toBase58()}`);

  const state0 = vaultState(await connection.getAccountInfo(v0.address));
  if (state0.kind === "spent") throw new Error(`vault[${index}] is already spent; use --index ${index + 1}`);

  const tombstoneRent = BigInt(await connection.getMinimumBalanceForRentExemption(TOMBSTONE_LEN));
  const zeroRent = BigInt(await connection.getMinimumBalanceForRentExemption(0));
  const remainder = depositLamports + state0.lamports - amount - tombstoneRent;
  if (remainder !== 0n && remainder < zeroRent) {
    throw new Error(`remainder ${remainder} lamports would be below rent; raise --deposit or adjust --amount`);
  }

  const record: Record<string, unknown> = {
    cluster,
    programId: PROGRAM_ID.toBase58(),
    payer: payer.publicKey.toBase58(),
    recipient: recipient.toBase58(),
    vault: v0.address.toBase58(),
    nextVault: v1.address.toBase58(),
    depositLamports: depositLamports.toString(),
    amount: amount.toString(),
    startedAt: new Date().toISOString(),
    transactions: {} as Record<string, string | string[]>,
  };
  const txs = record.transactions as Record<string, string | string[]>;

  if (depositLamports > 0n) {
    console.log("\n1. deposit");
    txs.deposit = await send("deposit", [depositSolIx({ from: payer.publicKey, vault: v0.address, lamports: depositLamports })]);
  } else {
    console.log(`\n1. deposit skipped; vault[${index}] already holds ${state0.lamports} lamports`);
  }

  console.log("\n2. sign with the WOTS key and stage the signature (3 transactions)");
  const plan = planSpend({ from: v0, nextVaultHash: v1.pkHash, recipient, amount, payer: payer.publicKey });
  console.log(`  digest:  ${bytesToHex(plan.digest)}`);
  console.log(`  buffer:  ${plan.buffer.toBase58()}`);
  const writes: string[] = [];
  for (let i = 0; i < plan.writeInstructions.length; i++) {
    writes.push(await send(`write ${i + 1}/${plan.writeInstructions.length}`, plan.writeInstructions[i]!));
  }
  txs.writeSignature = writes;

  // The RPC may be load-balanced: make sure the node we talk to has every chunk
  // before the withdraw is simulated against it.
  for (let attempt = 1; ; attempt++) {
    const account = await connection.getAccountInfo(plan.buffer, "confirmed");
    if (stagedPayloadMatches(account, plan.payload)) break;
    if (attempt > 30) throw new Error("staged signature never matched on this RPC node");
    console.log(`  buffer not fully visible yet (attempt ${attempt}), waiting…`);
    await new Promise((r) => setTimeout(r, 1000));
  }
  console.log("  buffer verified: on-chain payload matches the signature");

  console.log("\n3. withdraw: verify on-chain, pay recipient, roll remainder, tombstone");
  const recipientBefore = BigInt(await connection.getBalance(recipient));
  txs.withdraw = await send("withdraw", plan.withdrawInstructions);

  const withdrawTx = await connection.getTransaction(txs.withdraw, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
  const cu = withdrawTx?.meta?.computeUnitsConsumed;
  console.log(`  compute units consumed: ${cu ?? "?"}`);
  record.withdrawComputeUnits = cu ?? null;

  console.log("\n4. verify");
  const after0 = await connection.getAccountInfo(v0.address);
  const s0 = vaultState(after0);
  const v1Balance = BigInt(await connection.getBalance(v1.address));
  const recipientAfter = BigInt(await connection.getBalance(recipient));
  const bufferAfter = await connection.getAccountInfo(plan.buffer);
  if (s0.kind !== "spent") throw new Error("vault[0] is not a tombstone after the spend");
  if (!s0.tombstone.nextVault.equals(v1.address)) throw new Error("tombstone records the wrong next vault");
  if (v1Balance !== remainder) throw new Error(`next vault holds ${v1Balance}, expected ${remainder}`);
  if (bufferAfter !== null) throw new Error("signature buffer still exists");
  console.log(`  vault[${index}] is a tombstone holding ${s0.lamports} lamports, next = ${s0.tombstone.nextVault.toBase58()}`);
  console.log(`  vault[${index + 1}] holds ${v1Balance} lamports (the remainder)`);
  console.log(`  recipient ${recipient.equals(payer.publicKey) ? "(payer) " : ""}changed by ${recipientAfter - recipientBefore} lamports (amount ${amount}${recipient.equals(payer.publicKey) ? " plus the returned buffer rent, minus the fee" : ""})`);
  console.log(`  signature buffer closed, rent returned to payer`);
  record.result = {
    tombstoneLamports: s0.lamports.toString(),
    nextVaultLamports: v1Balance.toString(),
    recipientDelta: (recipientAfter - recipientBefore).toString(),
  };
  record.finishedAt = new Date().toISOString();

  mkdirSync(new URL("../../runs/", import.meta.url), { recursive: true });
  const out = new URL(`../../runs/${cluster}-cycle-${Date.now()}.json`, import.meta.url);
  writeFileSync(out, JSON.stringify(record, null, 2) + "\n");
  console.log(`\nrecord written to ${out.pathname}`);
}

main().catch((err) => {
  console.error(explain(err));
  process.exit(1);
});
