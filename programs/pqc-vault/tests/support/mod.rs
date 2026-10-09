// Each integration test binary pulls this module in separately, so helpers used by
// only one of them look dead to the other.
#![allow(dead_code)]

//! Shared fixture: a LiteSVM with the real Token programs, the vault program at
//! its real id, and helpers that drive a spend the way the TypeScript client does.

use litesvm::{types::TransactionResult, LiteSVM};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use pqc_vault::message::{spend_digest, SOL_MINT};
use pqc_vault::state::{SigBuffer, Tombstone};
use pqc_vault::wots::{signer as wots_signer, N, SIG_LEN};
use pqc_vault::{IX_CLOSE_BUFFER, IX_SWEEP, IX_WITHDRAW, IX_WRITE_SIGNATURE, KIND_SOL, KIND_TOKEN};

pub const ERR_INVALID_SIGNATURE: u32 = 6000;
pub const ERR_VAULT_ALREADY_SPENT: u32 = 6001;
pub const ERR_UNEXPECTED_VAULT_STATE: u32 = 6002;
pub const ERR_INVALID_BUFFER: u32 = 6003;
pub const ERR_BUFFER_DIGEST_MISMATCH: u32 = 6004;
pub const ERR_BUFFER_VAULT_MISMATCH: u32 = 6005;
pub const ERR_BUFFER_PAYER_MISMATCH: u32 = 6006;
pub const ERR_WRITE_OUT_OF_BOUNDS: u32 = 6007;
pub const ERR_INVALID_NEXT_VAULT: u32 = 6008;
pub const ERR_NEXT_VAULT_IS_SELF: u32 = 6009;
pub const ERR_NEXT_VAULT_ALREADY_SPENT: u32 = 6010;
pub const ERR_RECIPIENT_IS_VAULT: u32 = 6011;
pub const ERR_INSUFFICIENT_FUNDS: u32 = 6012;
pub const ERR_BELOW_RENT_EXEMPTION: u32 = 6013;
pub const ERR_INVALID_TOKEN_PROGRAM: u32 = 6014;
pub const ERR_INVALID_MINT: u32 = 6015;
pub const ERR_INVALID_TOKEN_ACCOUNT: u32 = 6016;
pub const ERR_INVALID_ATA_PROGRAM: u32 = 6017;
pub const ERR_INVALID_SYSTEM_PROGRAM: u32 = 6018;
pub const ERR_NOT_A_TOMBSTONE: u32 = 6019;
pub const ERR_INVALID_KIND: u32 = 6020;

pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
/// The largest chunk the client sends per WriteSignature transaction.
pub const CHUNK: usize = 900;

/// Program crate types are the 2.x SDK generation; the test harness is on 4.x.
/// Keys cross the boundary as bytes.
pub fn to_test(key: &solana_program::pubkey::Pubkey) -> Pubkey {
    Pubkey::new_from_array(key.to_bytes())
}

pub fn to_program(key: &Pubkey) -> solana_program::pubkey::Pubkey {
    solana_program::pubkey::Pubkey::new_from_array(key.to_bytes())
}

pub fn program_id() -> Pubkey {
    to_test(&pqc_vault::ID)
}

pub fn system_program() -> Pubkey {
    Pubkey::new_from_array([0u8; 32])
}

pub fn token_2022() -> Pubkey {
    to_test(&pqc_vault::token::TOKEN_2022_PROGRAM_ID)
}

pub fn token_classic() -> Pubkey {
    to_test(&pqc_vault::token::TOKEN_PROGRAM_ID)
}

pub fn ata_program() -> Pubkey {
    to_test(&pqc_vault::token::ATA_PROGRAM_ID)
}

pub fn ata(owner: &Pubkey, token_program: &Pubkey, mint: &Pubkey) -> Pubkey {
    to_test(&pqc_vault::token::associated_token_address(
        &to_program(owner),
        &to_program(token_program),
        &to_program(mint),
    ))
}

/// Deterministic test randomness (splitmix64).
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    pub fn bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..chunk.len()]);
        }
        out
    }
}

/// One vault's WOTS key: what the browser holds for one vault index.
pub struct VaultKey {
    pub sk_seed: [u8; N],
    pub pub_seed: [u8; N],
    pub pk_hash: [u8; N],
    pub address: Pubkey,
    pub bump: u8,
}

impl VaultKey {
    pub fn from_seeds(sk_seed: [u8; N], pub_seed: [u8; N]) -> Self {
        let pk = wots_signer::public_key(&sk_seed, &pub_seed);
        let pk_hash = wots_signer::pk_hash(&pk);
        let (address, bump) = pqc_vault::vault_address(&pk_hash);
        Self {
            sk_seed,
            pub_seed,
            pk_hash,
            address: to_test(&address),
            bump,
        }
    }

    pub fn random(rng: &mut Rng) -> Self {
        Self::from_seeds(rng.bytes32(), rng.bytes32())
    }

    pub fn sign(&self, digest: &[u8; N]) -> Vec<u8> {
        wots_signer::sign(&self.sk_seed, &self.pub_seed, digest)
    }

    /// `pubSeed ‖ signature`: the buffer payload.
    pub fn payload(&self, digest: &[u8; N]) -> Vec<u8> {
        let mut out = self.pub_seed.to_vec();
        out.extend(self.sign(digest));
        out
    }
}

pub fn digest_for(
    vault: &Pubkey,
    recipient: &Pubkey,
    mint: Option<&Pubkey>,
    amount: u64,
    next_vault_hash: &[u8; 32],
) -> [u8; 32] {
    spend_digest(
        &pqc_vault::ID,
        &to_program(vault),
        &to_program(recipient),
        &mint.map_or(SOL_MINT, to_program),
        amount,
        next_vault_hash,
    )
}

pub fn buffer_address(vault: &Pubkey, digest: &[u8; 32], payer: &Pubkey) -> Pubkey {
    to_test(&pqc_vault::buffer_address(&to_program(vault), digest, &to_program(payer)).0)
}

fn so_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy/pqc_vault.so")
}

/// Everything a token spend needs beyond the SOL accounts.
pub struct TokenSpend {
    pub mint: Pubkey,
    pub token_program: Pubkey,
    pub extra: Vec<AccountMeta>,
}

pub struct Fixture {
    pub svm: LiteSVM,
    pub payer: Keypair,
}

impl Fixture {
    pub fn new() -> Self {
        let mut svm = LiteSVM::new();
        let so = std::fs::read(so_path()).unwrap_or_else(|err| {
            panic!(
                "could not read {} ({err}). Run `cargo build-sbf` before `cargo test`.",
                so_path().display()
            )
        });
        svm.add_program(program_id(), &so).unwrap();
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 1_000 * LAMPORTS_PER_SOL)
            .unwrap();
        Self { svm, payer }
    }

    pub fn payer_pubkey(&self) -> Pubkey {
        self.payer.pubkey()
    }

    pub fn payer_clone(&self) -> Keypair {
        self.payer.insecure_clone()
    }

    #[allow(clippy::result_large_err)]
    pub fn send(&mut self, ixs: &[Instruction], signers: &[&Keypair]) -> TransactionResult {
        let message = Message::new(ixs, Some(&self.payer.pubkey()));
        let tx = Transaction::new(signers, message, self.svm.latest_blockhash());
        let result = self.svm.send_transaction(tx);
        // A fresh blockhash keeps litesvm from rejecting a later identical tx.
        self.svm.expire_blockhash();
        result
    }

    /// Sends with the payer alone, with a generous compute budget so the
    /// consumed figure is the real one.
    #[allow(clippy::result_large_err)]
    pub fn send_budgeted(&mut self, ixs: &[Instruction]) -> TransactionResult {
        let mut all = vec![ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)];
        all.extend_from_slice(ixs);
        let payer = self.payer_clone();
        self.send(&all, &[&payer])
    }

    pub fn airdrop(&mut self, to: &Pubkey, lamports: u64) {
        self.svm.airdrop(to, lamports).unwrap();
    }

    pub fn balance(&self, key: &Pubkey) -> u64 {
        self.svm.get_account(key).map_or(0, |a| a.lamports)
    }

    pub fn owner(&self, key: &Pubkey) -> Option<Pubkey> {
        self.svm.get_account(key).map(|a| a.owner)
    }

    pub fn data(&self, key: &Pubkey) -> Vec<u8> {
        self.svm.get_account(key).map_or(Vec::new(), |a| a.data)
    }

    pub fn rent_for(&self, len: usize) -> u64 {
        self.svm.minimum_balance_for_rent_exemption(len)
    }

    pub fn tombstone_rent(&self) -> u64 {
        self.rent_for(Tombstone::LEN)
    }

    pub fn buffer_rent(&self) -> u64 {
        self.rent_for(SigBuffer::LEN)
    }

    // ----- instruction builders (mirror the TypeScript client) -----

    pub fn write_ix(
        &self,
        payer: &Pubkey,
        vault: &Pubkey,
        digest: &[u8; 32],
        offset: u16,
        chunk: &[u8],
    ) -> Instruction {
        let buffer = buffer_address(vault, digest, payer);
        let mut data = vec![IX_WRITE_SIGNATURE];
        data.extend_from_slice(vault.as_ref());
        data.extend_from_slice(digest);
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(chunk);
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(*payer, true),
                AccountMeta::new(buffer, false),
                AccountMeta::new_readonly(system_program(), false),
            ],
            data,
        }
    }

    pub fn close_buffer_ix(&self, payer: &Pubkey, buffer: &Pubkey) -> Instruction {
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(*payer, true),
                AccountMeta::new(*buffer, false),
            ],
            data: vec![IX_CLOSE_BUFFER],
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn withdraw_ix(
        &self,
        payer: &Pubkey,
        buffer: &Pubkey,
        buffer_payer: &Pubkey,
        vault: &Pubkey,
        next_vault: &Pubkey,
        recipient: &Pubkey,
        amount: u64,
        next_vault_hash: &[u8; 32],
        token: Option<&TokenSpend>,
    ) -> Instruction {
        let mut data = vec![
            IX_WITHDRAW,
            if token.is_some() {
                KIND_TOKEN
            } else {
                KIND_SOL
            },
        ];
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(next_vault_hash);
        let mut accounts = vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*buffer, false),
            AccountMeta::new(*buffer_payer, false),
            AccountMeta::new(*vault, false),
            AccountMeta::new(*next_vault, false),
            AccountMeta::new(*recipient, false),
            AccountMeta::new_readonly(system_program(), false),
        ];
        if let Some(t) = token {
            accounts.extend([
                AccountMeta::new_readonly(t.mint, false),
                AccountMeta::new(ata(vault, &t.token_program, &t.mint), false),
                AccountMeta::new(ata(recipient, &t.token_program, &t.mint), false),
                AccountMeta::new(ata(next_vault, &t.token_program, &t.mint), false),
                AccountMeta::new_readonly(t.token_program, false),
                AccountMeta::new_readonly(ata_program(), false),
            ]);
            accounts.extend(t.extra.iter().cloned());
        }
        Instruction {
            program_id: program_id(),
            accounts,
            data,
        }
    }

    pub fn sweep_sol_ix(&self, vault: &Pubkey, next_vault: &Pubkey) -> Instruction {
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(*vault, false),
                AccountMeta::new(*next_vault, false),
                AccountMeta::new_readonly(system_program(), false),
            ],
            data: vec![IX_SWEEP, KIND_SOL, 0],
        }
    }

    pub fn sweep_token_ix(
        &self,
        payer: &Pubkey,
        vault: &Pubkey,
        next_vault: &Pubkey,
        token: &TokenSpend,
        close_ata: bool,
    ) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new(*vault, false),
            AccountMeta::new(*next_vault, false),
            AccountMeta::new_readonly(system_program(), false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(token.mint, false),
            AccountMeta::new(ata(vault, &token.token_program, &token.mint), false),
            AccountMeta::new(ata(next_vault, &token.token_program, &token.mint), false),
            AccountMeta::new_readonly(token.token_program, false),
            AccountMeta::new_readonly(ata_program(), false),
        ];
        accounts.extend(token.extra.iter().cloned());
        Instruction {
            program_id: program_id(),
            accounts,
            data: vec![IX_SWEEP, KIND_TOKEN, u8::from(close_ata)],
        }
    }

    // ----- flows -----

    /// Writes `payload` into the buffer in client-sized chunks, one tx each.
    /// Returns the buffer address.
    pub fn stage(
        &mut self,
        payer: &Keypair,
        vault: &Pubkey,
        digest: &[u8; 32],
        payload: &[u8],
    ) -> Pubkey {
        assert_eq!(payload.len(), N + SIG_LEN);
        for (i, chunk) in payload.chunks(CHUNK).enumerate() {
            let ix = self.write_ix(&payer.pubkey(), vault, digest, (i * CHUNK) as u16, chunk);
            let fee_payer = self.payer_clone();
            let signers: Vec<&Keypair> = if payer.pubkey() == fee_payer.pubkey() {
                vec![&fee_payer]
            } else {
                vec![&fee_payer, payer]
            };
            self.send(&[ix], &signers)
                .unwrap_or_else(|e| panic!("write chunk {i}: {:#?}", e.meta.logs));
        }
        buffer_address(vault, digest, &payer.pubkey())
    }

    /// The whole client flow for a SOL spend: digest, WOTS sign, stage, withdraw.
    #[allow(clippy::result_large_err)]
    pub fn spend_sol(
        &mut self,
        from: &VaultKey,
        to: &VaultKey,
        recipient: &Pubkey,
        amount: u64,
    ) -> TransactionResult {
        let digest = digest_for(&from.address, recipient, None, amount, &to.pk_hash);
        let payer = self.payer_clone();
        let buffer = self.stage(&payer, &from.address, &digest, &from.payload(&digest));
        let ix = self.withdraw_ix(
            &payer.pubkey(),
            &buffer,
            &payer.pubkey(),
            &from.address,
            &to.address,
            recipient,
            amount,
            &to.pk_hash,
            None,
        );
        self.send_budgeted(&[ix])
    }

    /// The whole client flow for a token spend.
    #[allow(clippy::result_large_err)]
    pub fn spend_token(
        &mut self,
        from: &VaultKey,
        to: &VaultKey,
        recipient: &Pubkey,
        token: &TokenSpend,
        amount: u64,
    ) -> TransactionResult {
        let digest = digest_for(
            &from.address,
            recipient,
            Some(&token.mint),
            amount,
            &to.pk_hash,
        );
        let payer = self.payer_clone();
        let buffer = self.stage(&payer, &from.address, &digest, &from.payload(&digest));
        let ix = self.withdraw_ix(
            &payer.pubkey(),
            &buffer,
            &payer.pubkey(),
            &from.address,
            &to.address,
            recipient,
            amount,
            &to.pk_hash,
            Some(token),
        );
        self.send_budgeted(&[ix])
    }

    // ----- tokens -----

    pub fn create_mint(&mut self, token_program: &Pubkey, decimals: u8) -> Pubkey {
        let mint = Keypair::new();
        // A mint with no extensions is 82 bytes under both token programs.
        let space = 82;
        let ixs = [
            solana_system_interface::instruction::create_account(
                &self.payer.pubkey(),
                &mint.pubkey(),
                self.rent_for(space),
                space as u64,
                token_program,
            ),
            spl_token_2022_interface::instruction::initialize_mint2(
                token_program,
                &mint.pubkey(),
                &self.payer.pubkey(),
                None,
                decimals,
            )
            .unwrap(),
        ];
        let payer = self.payer_clone();
        self.send(&ixs, &[&payer, &mint]).expect("create mint");
        mint.pubkey()
    }

    /// Creates `owner`'s ATA if needed and mints `amount` into it.
    pub fn mint_to(
        &mut self,
        token_program: &Pubkey,
        mint: &Pubkey,
        owner: &Pubkey,
        amount: u64,
    ) -> Pubkey {
        let destination = ata(owner, token_program, mint);
        let ixs = [
            spl_associated_token_account_interface::instruction::create_associated_token_account_idempotent(
                &self.payer.pubkey(),
                owner,
                mint,
                token_program,
            ),
            spl_token_2022_interface::instruction::mint_to(
                token_program,
                mint,
                &destination,
                &self.payer.pubkey(),
                &[],
                amount,
            )
            .unwrap(),
        ];
        let payer = self.payer_clone();
        self.send(&ixs, &[&payer]).expect("mint to");
        destination
    }

    pub fn token_balance(&self, account: &Pubkey) -> u64 {
        let data = self.data(account);
        if data.len() < 72 {
            return 0;
        }
        u64::from_le_bytes(data[64..72].try_into().unwrap())
    }
}

pub fn assert_custom_error(result: TransactionResult, expected: u32) {
    use solana_instruction::error::InstructionError;
    use solana_transaction_error::TransactionError;
    match result {
        Ok(meta) => panic!(
            "expected custom error {expected}, but it succeeded: {:#?}",
            meta.logs
        ),
        Err(failed) => match failed.err {
            TransactionError::InstructionError(_, InstructionError::Custom(code))
                if code == expected => {}
            other => panic!(
                "expected custom error {expected}, got {other:?}\n{:#?}",
                failed.meta.logs
            ),
        },
    }
}

/// This program's own compute line from the logs (CPIs included).
pub fn program_compute_units(logs: &[String]) -> u64 {
    let marker = format!("Program {} consumed ", program_id());
    logs.iter()
        .find_map(|line| line.strip_prefix(&marker))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no compute line in logs: {logs:#?}"))
}
