# pqc-vault

Solana vaults that only a post-quantum, hash-based signature can move. A vault's
funds are controlled by a Winternitz one-time key (WOTS, w = 16, SHA-256) that
the pqc.market web app derives in the browser. The program verifies that
signature itself with the `sol_sha256` syscall. No ed25519 key has any authority
over vault funds, so an ed25519 break does not reach them.

## Status

| Item | Value |
| --- | --- |
| Program ID (devnet and mainnet) | `DNsPfPecrbnS7jFqMpEDG3VoWAdkuaU2VxsmaPENcg9F` |
| Devnet | deployed, full cycle run (signatures below) |
| Mainnet | **deployed**, tx `3ptyadDUa5SNreoyZdjQVERVSrsR4LAzV9L7eMPTpcCbkU2TeyGRxSPLKbJvzypH5XKfXHK9Sbefy2sjG82sMm48` (slot 454708455); full cycle run (signatures below) |
| Mainnet binary sha256 | `f25aaa944abd823e397e6be732b9c5bd19880a8af87da130faee7eb44e9d6574` = `sha256sum target/deploy/pqc_vault.so` |
| Devnet binary | built from the same source before a `cargo fmt` pass; differs only in line numbers embedded in panic locations. Re-run `./deploy.sh devnet keys/devnet-deployer.json` with ~1 SOL on that key to make it byte-identical. |
| Devnet upgrade authority | `7DTD3gAa2BE2JGN1Y7YA6B74bjRowMVXfcXidxgH4wvb` (throwaway key in `keys/devnet-deployer.json`) |
| Mainnet upgrade authority | `ESobDnh3gjhwhKyZuEoTNqeNNT33xPjkk7eRhwfVfMJi`, the deployer from `.env`. **Not finalized**: this key can still change the program. See the runbook to make it immutable. |
| Frontend handoff | `HANDOFF.md` |
| Binary | 120,472 bytes, native `solana-program` 2.3, no Anchor |
| Tests | 21 Rust tests (litesvm, real Token / Token-2022 / ATA programs), 7 TypeScript tests, shared vectors checked by both |

The program ID is the same on both clusters because the program keypair in
`keys/pqc_vault-program-keypair.json` is used for both and the ID is baked into
the binary with `declare_id!`. Keep that keypair: without it the program cannot
be deployed to this ID on mainnet.

### Devnet cycle (deposit → withdraw → next vault)

Run with a throwaway test identity (seed withheld: it still controls the vault the remainder rolled into).

| Step | Signature |
| --- | --- |
| Deploy | `4voauCFsVCa7agcdzH9HxtM8ZiRVhDnaJwdaKVesPpRKrVXFRYVwBtj58Dy9CrzDzZ7qc1uiCwQaooxaoEnf9XHr` |
| Deposit 0.01 SOL to vault[0] `GBquDpqP7ccVWizPDweyxHiwcLVUuVTnRy8i7m3V4Lxw` | `4q7VkctMh1KErUncVMPKdQs2Gg6dJnrWZANUuQYmFW5nBigcMAJLKE5uiFHZLhG7Xub4HupD2gmGoZDss766YTGx` |
| Write signature 1/3 | `5r7xnRETuqMpzvmEE7ZTcRcyV6VPpba2HxGN1UXEoSxezPL2NZN3DyjS4uNh9BtZxTWeeqn2ArxShP6Qx9LHD23u` |
| Write signature 2/3 | `5fSxXLX8C8PeXYCT94SRSzdmsyBP3Yx5ALCuEmimXaDoMzsmgKYjugpNrfeYXS5nsKvvScAtLzQi1s8akhk4NRbP` |
| Write signature 3/3 | `346S4Aktx9RwLyWeyGmVK3hpt3CArZBZ3WwrDNxJWRQxVLNjmtoyw4cBgkX315fGCc254SE7QuF57ny5XBxSbBpy` |
| Withdraw 0.004 SOL, roll the rest into vault[1] `4GQsUL92UJ1w4wDvQjcwx8zXMKvZyXZdMLXMLF2cf5PV` | `5cntxu9u3una1qHgDGGFn15RFX2cJ2rVFCN2MX7NT9j5YLkLHgb7LC6ck42DyF3YiyL6vaBxU9BezP4gf1Bz6W6u` |

The withdraw consumed 106,498 CU. Afterwards vault[0] is a 67-byte tombstone
holding its own rent (990,600 lamports), vault[1] holds the remainder
(5,009,400 lamports), the signature buffer is closed and its rent is back with
the payer. Record: `runs/devnet-cycle-*.json`.

### Mainnet cycle (deposit → withdraw → next vault)

Payer and recipient `ESobDnh3gjhwhKyZuEoTNqeNNT33xPjkk7eRhwfVfMJi`, throwaway test
identity (seed withheld: it still controls vault[1]).

| Step | Signature |
| --- | --- |
| Deposit 0.01 SOL to vault[0] `494BWnxAs9fRBsjR49UMU9VAMTBHxiwjnLh6C81JDZMP` | `159g8gUT4P1rc1txCAZoYiLSPLhB4rEm4giqQHkSxoTEdkR75n2tG3XtYVj3R91UnF7xYSW2hEsUS3xk8ZdXSV2` |
| Write signature 1/3 | `3rCRn9YYcrE8pY8KVfooaq2hxLJCp142fGdUPLfw1sd8zoewWoKmQLjCnBQ5nvh6qSQ7dGj23fG4LCsepjbPPoC9` |
| Write signature 2/3 | `3mWiisMpmN5LpG5xKB4gzQaxwjmauHHyHYZHnFdTX1jGhK4z8E3UdjNg5PPuMFEKoBNC7kQg3T3es97K8hXjCyRT` |
| Write signature 3/3 | `4HsVd5Ac1GhBhnQru2fkkAxcmtPXnQJtiTArNQVtE3n4BMGYQSxeTt8KK1vFjUB9BuRPqcQBSDJooKGyfSNACGQD` |
| Withdraw 0.004 SOL, roll the rest into vault[1] `PrK9yX1eXuqMUQLV9gCnq71xVSVaNgks8eoMXrbmf7z` | `54SNCqbvpww9Ubu1Kv3FePAw3jJp5fJHJaG4CTv6fFrHFMA3qBAmA4yDUAC5Mdz4yU9tXFScZ4mR33cK5DCmXtt` |

The withdraw consumed 125,839 CU. vault[0] is a tombstone (990,600 lamports,
next = vault[1]), vault[1] holds 5,009,400 lamports, the buffer is closed.
Record: `runs/mainnet-cycle-*.json`.

The first withdraw attempt on mainnet failed with `InvalidSignature` after the
same three chunks (`3AmS9w…`, `4pUJUk…`, `5jHDzK…`) had confirmed. Helius
load-balances RPC nodes, and the node that simulated the withdraw had not yet
applied the last chunk, so the program verified a partial buffer. The client
now has `stagedPayloadMatches` and the cycle script reads the buffer back until
it matches before sending the withdraw; the resumed run (same identity, same
message, `--deposit 0`) went through. Re-staging the same signature was safe
because it is the same message; see the operating rules.

## Compute and size

From `vectors/compute.json` (written by the `compute` test):

| Figure | Value |
| --- | --- |
| Cost per chain step (one 96-byte SHA-256) | 179 CU |
| Fixed cost of a SOL withdraw | 25,286 CU |
| Typical SOL withdraw (around 500 steps) | 95k to 126k CU |
| **Worst-case SOL withdraw** (all-zero digest, 990 steps, plus a 45k CU margin for an unlucky PDA bump search) | **247,272 CU** |
| Token-2022 CPI overhead (two ATA creates, two transfers) | 50,893 CU |
| **Worst-case Token-2022 withdraw** | **298,165 CU** |
| Limit | 1,400,000 CU |

Cost is linear in the number of chain steps (sum over 67 chains of `15 − dᵢ`),
which is a property of the digest, so the worst case is exact rather than
sampled. The client requests 300k CU for SOL spends and 400k for token spends.

Sizes: signature 2,144 bytes; staged payload (`pubSeed ‖ signature`) 2,176
bytes; buffer account 2,273 bytes; tombstone 67 bytes.

Rent (both clusters today): buffer 12,197,080 lamports, refunded when the spend
lands; tombstone 990,600 lamports, locked forever per spent vault. That lock is
the price of one-time-ness: the spent address has to stay occupied so the key
can never be spent twice.

## How it works

**Vault.** A PDA at `["vault", version = 1, SHA-256(wots_public_key)]`, a plain
system account with no data. The address reveals only a hash of the key until
the first spend.

**Deposit.** Send SOL to the address, or tokens to its associated token account
(create it idempotently first). No signature, no program instruction.

**Withdraw.** Two phases because a signature does not fit in one transaction
(2,176 bytes against a 1,232-byte limit).

1. `WriteSignature` ×3: the payer stages `pubSeed ‖ signature` in a buffer PDA
   at `["sig", vault, digest, payer]`. Chunks of 850 bytes, independent
   transactions. Including the payer in the seeds means nobody can squat a
   buffer address they saw in the mempool; the buffer can only be written and
   closed by its payer.
2. `Withdraw`: the program
   - rebuilds the digest from the instruction's own parameters (it never trusts
     a supplied digest) and requires the buffer to be bound to exactly that
     digest, vault and payer;
   - recovers the WOTS public key from the staged signature, hashes it, derives
     the vault PDA from the hash and requires it to equal the vault account.
     That is the entire authority check;
   - token spend: `amount` of the mint to the recipient's ATA, the rest of that
     mint to `next_vault`'s ATA (both created if missing, payer funds them);
   - turns the vault into a **tombstone**: allocates 67 bytes, assigns the
     account to the program, writes `{version, bump, pk_hash, next_vault}`;
   - SOL: `amount` to the recipient (SOL spend) and everything above the
     tombstone's rent to `next_vault`;
   - closes the buffer, rent back to whoever staged it.

**One-time.** The tombstone keeps the PDA address occupied and program-owned.
Any later `Withdraw` against it fails with `VaultAlreadySpent` before anything
is verified. The signed message commits to `next_vault_hash`, and the program
derives `next_vault` from that hash, so the remainder can only go to another
vault of this program, which must itself be unspent.

**Sweep.** Deposits that arrive after a spend (SOL, or any mint) would otherwise
be stuck at the tombstone. `Sweep` is permissionless and forwards them to the
`next_vault` recorded in the tombstone, nowhere else. It is also how a spend's
emptied token account gets closed (its rent goes to `next_vault`). That step is
kept out of `Withdraw` on purpose: a mint quirk such as withheld transfer fees
or a strict transfer hook can then never make a one-time signature's spend fail.

**Signed message.**

```
digest = SHA-256(
  "pqc.market/vault-spend/v1" ‖ program_id ‖ vault ‖ recipient
  ‖ mint (32 zero bytes for SOL) ‖ amount (u64 little-endian) ‖ next_vault_hash
)
```

Everything that could let a signature be reused somewhere else is bound: the
program and version, the vault, the destination, the asset, the amount, the
next vault.

### Instructions

| Tag | Instruction | Accounts | Data after the tag |
| --- | --- | --- | --- |
| 0 | WriteSignature | payer (s, w), buffer (w), system | `vault(32) ‖ digest(32) ‖ offset(u16 LE) ‖ chunk` |
| 1 | Withdraw | payer (s, w), buffer (w), buffer_payer (w), vault (w), next_vault (w), recipient (w), system, then for tokens: mint, vault_ata (w), recipient_ata (w), next_vault_ata (w), token_program, ata_program, hook extras… | `kind(u8: 0 SOL, 1 token) ‖ amount(u64 LE) ‖ next_vault_hash(32)` |
| 2 | CloseBuffer | payer (s, w), buffer (w) | none |
| 3 | Sweep | vault (w), next_vault (w), system, then for tokens: payer (s, w), mint, vault_ata (w), next_vault_ata (w), token_program, ata_program, hook extras… | `kind(u8) ‖ close_ata(u8)` |

Error codes 6000 to 6020 are listed in `programs/pqc-vault/src/error.rs` and
mapped to messages in the client's `ERRORS` table.

## Crypto

Exactly as specified, implemented twice (Rust in
`programs/pqc-vault/src/wots.rs`, TypeScript in `client/src/wots.ts`) and
pinned to each other by `vectors/wots.json`:

- SHA-256, n = 32.
- ADRS: 32 bytes, big-endian u32 `type | a | b | c` at offsets 0, 4, 8, 12,
  then 16 zero bytes. Type 0 = chain step, 3 = secret PRF.
- `F(pubSeed, ADRS, x) = SHA-256(pubSeed ‖ ADRS ‖ x)`.
- 64 nibbles (high then low per byte), checksum `C = Σ(15 − dᵢ)` as three
  nibbles `(C>>8)&15, (C>>4)&15, C&15`, 67 chains.
- `skᵢ = SHA-256(skSeed ‖ ADRS(3, leaf, i, 0))`; step at position s:
  `x ← F(pubSeed, ADRS(0, leaf, i, s), x)`; `pkᵢ` = `skᵢ` walked 15 steps;
  `σᵢ` = `skᵢ` walked `dᵢ` steps; verify by walking `σᵢ` from `dᵢ` to 14.

Choices the spec left open. **These must match in the web app**, so check them
against its code:

| Choice | Value |
| --- | --- |
| `wots_public_key` as hashed into the vault address | `pubSeed ‖ pk₀ ‖ … ‖ pk₆₆` (2,176 bytes). Including `pubSeed` makes the address commit to the whole key, and the verifier needs nothing but the staged payload. |
| ADRS leaf field for vault keys | `0`. Vault seeds are already per-vault, so a vault key is a standalone key, not a tree leaf. |
| Per-vault seeds | `skSeedᵢ = HKDF-SHA256(ikm = identity.skSeed, salt = empty, info = "pqc.market/vault/v1/sk" ‖ u32be(i), 32)` and `pubSeedᵢ = HKDF-SHA256(ikm = identity.pubSeed, salt = empty, info = "pqc.market/vault/v1/pub" ‖ u32be(i), 32)` |
| SOL in the message | 32 zero bytes in the mint slot |
| Amount encoding | u64 little-endian |
| Vault version byte | `1` |

Vectors: `vectors/wots.json` (five WOTS cases including the 990-step worst case
and the 45-step best case, with every intermediate: steps, `sk₀`, `sk₆₆`,
`pk₀`, full public key, its hash, the signature) and `vectors/vault.json`
(identity → HKDF seeds → keys → addresses for three indices, a SOL spend and a
Token-2022 spend with digest, buffer address and full payload). The Rust test
`vectors.rs` recomputes all of it independently, including the HKDF, and then
has the program accept the TypeScript-signed payload in litesvm. Run the same
files through the web app's implementation before pointing it at mainnet.

## Security notes and operating rules

- **Sign once per vault.** `VaultKey.signSpend` / `planSpend` is the only place
  a vault key signs. If a withdraw fails for an environmental reason (RPC,
  blockhash, a missing account), resubmit the *same* plan. Never sign a second,
  different message with the same vault key: two signatures from one WOTS key
  leak enough to forge. The program cannot stop that; the client must.
- **Read the buffer back before Withdraw.** With a load-balanced RPC the
  simulating node may lag the confirming one; a partial buffer fails as
  `InvalidSignature`. `stagedPayloadMatches(accountInfo, plan.payload)` must be
  true on the node you send through.
- Once the signature is staged on-chain it is public. That is fine: it only
  authorises the exact message it signed, and anyone submitting the withdraw
  just performs the spend the owner asked for.
- Nothing moves without a valid signature, with one deliberate exception:
  `Sweep` moves funds from a *spent* vault to the `next_vault` its owner
  already signed over. There is no parameter a caller can influence.
- Stray lamports at a vault or buffer address never block anything: the
  program tops up and allocates in place rather than requiring a fresh account.
- If a vault holds no SOL (tokens only), the payer funds the tombstone rent
  (990,600 lamports).
- A SOL spend whose remainder would be below the rent floor fails with
  `BelowRentExemption`; spend everything or leave at least 650,240 lamports.
- Transfer hooks: pass the resolved extra accounts in `TokenSpend.extraAccounts`;
  the program forwards them to both transfers. Most pump.fun coins need none.
- Other mints held by a vault are not moved by `Withdraw` (one instruction
  cannot enumerate them). Sweep each one from the tombstone afterwards; the
  client's `buildSweepInstructions` does this for a list of mints.
- The program checks `program_id == declare_id!` and derives every PDA itself;
  bumps are never taken from input.

## Layout

```
programs/pqc-vault/      the program (native, solana-program 2.3)
  src/wots.rs            verifier (+ signer for tests, never compiled on-chain)
  src/withdraw.rs        the spend
  src/write_signature.rs, close_buffer.rs, sweep.rs
  src/state.rs           buffer and tombstone layouts
  src/token.rs           hand-built Token / Token-2022 / ATA CPIs
  tests/                 litesvm suite: vault.rs, tokens.rs, compute.rs, vectors.rs
client/                  @pqc-market/vault-client (TypeScript, @noble/hashes + @solana/web3.js)
  src/wots.ts, vault.ts, instructions.ts, transactions.ts, state.ts
  scripts/gen-vectors.ts regenerates vectors/
  scripts/cycle.ts       one full cycle on a live cluster
vectors/                 wots.json, vault.json, compute.json
runs/                    records of live cycles
keys/                    program keypair + devnet deployer (gitignored)
deploy.sh, scripts/prepare_deploy.py, .env.example
```

## Build and test

```bash
cargo build-sbf                 # target/deploy/pqc_vault.so
cargo test                      # 21 tests, needs the .so above
cd client && npm install && npm test && npm run build
npm run vectors                 # regenerate vectors/*.json (then re-run cargo test)
```

## Client

```ts
import { VaultKey, planSpend, depositSolIx, vaultState, TOKEN_2022_PROGRAM_ID } from "@pqc-market/vault-client";

// identity = { skSeed, pubSeed } from the wallet-signature derivation, in memory only
const v0 = VaultKey.fromIdentity(identity, 0);
const v1 = VaultKey.fromIdentity(identity, 1);
v0.address;                      // deposit address, show it to the user

// deposit: any wallet
depositSolIx({ from: wallet, vault: v0.address, lamports: 1_000_000_000n });

// spend: signs with the WOTS key once, lays out every transaction
const plan = planSpend({
  from: v0, nextVaultHash: v1.pkHash,
  recipient, amount: 250_000_000n, payer: wallet,
  // token: { mint, tokenProgram: TOKEN_2022_PROGRAM_ID }
});
plan.writeInstructions;          // 3 tx, send in parallel, confirm all
plan.withdrawInstructions;       // 1 tx (compute budget + withdraw)
plan.cleanupInstructions;        // token spends: closes the emptied vault ATA
plan.abortInstructions;          // reclaim buffer rent if you give up

vaultState(await connection.getAccountInfo(v0.address)); // "unspent" | "spent" + tombstone
```

`buildWithdrawTransactions(req, blockhash)` wraps the same plan into legacy
`Transaction`s. Nothing in the client talks to the network and no seed leaves
the caller.

## Deploy

```bash
cp .env.example .env            # fill DEPLOYER_PRIVATE_KEY and MAINNET_RPC_URL
./deploy.sh devnet              # or: ./deploy.sh devnet keys/devnet-deployer.json
./deploy.sh mainnet
```

The script builds, runs the tests, shows the deployer, program ID and balance,
warns if it is about to upgrade a live program, and deploys with the deployer
as upgrade authority. A 120 KB program costs about 0.85 SOL of rent on
mainnet, plus an equal amount held in a buffer during the deploy and returned
afterwards, so fund the deployer with about 2 SOL.

### Mainnet runbook

Steps 1 to 3 are done (see Status). Re-run step 3 any time to re-verify; use
`--deposit 0 --identity <seed> --index <n>` to resume a cycle whose withdraw did
not land.

1. Put the key and a private RPC URL in `.env`, fund the deployer with ~2 SOL.
2. `./deploy.sh mainnet` (re-running upgrades the live program).
3. One cycle: `cd client && npm run cycle -- --rpc <MAINNET_RPC_URL> --payer <payer.json> --cluster mainnet`.
4. **Open decision: the upgrade authority.** It is the deployer
   `ESobDnh3gjhwhKyZuEoTNqeNNT33xPjkk7eRhwfVfMJi`. While it exists, that one
   ed25519 key can change the rules for every vault, which undercuts the
   post-quantum story. To make the program immutable:
   `solana program set-upgrade-authority DNsPfPecrbnS7jFqMpEDG3VoWAdkuaU2VxsmaPENcg9F --final --url <rpc> --keypair <deployer>`.
   Do that only once the web app has been checked against `vectors/`: after
   finalizing, any mismatch means a new program ID.
