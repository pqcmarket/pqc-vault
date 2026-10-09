//! Withdraw: the one spend a vault ever makes.
//!
//! 1. Rebuild the message from the parameters and bind the buffer to it.
//! 2. Recover the WOTS public key from the staged signature; its hash must
//!    derive this vault's address. That is the only authority check.
//! 3. For a token spend: `amount` to the recipient's ATA, the rest of that mint
//!    to `next_vault`'s ATA.
//! 4. Turn the vault into a tombstone (program-owned, keeps its own rent).
//! 5. SOL: `amount` to the recipient (SOL spend) and everything else to
//!    `next_vault`.
//! 6. Close the buffer back to whoever funded it.
//!
//! Accounts:
//! ```text
//! 0 payer         signer, writable   pays ATA creation and tombstone top-up
//! 1 buffer        writable           staged signature, closed here
//! 2 buffer_payer  writable           receives the buffer rent
//! 3 vault         writable
//! 4 next_vault    writable           PDA of next_vault_hash, must be unspent
//! 5 recipient     writable
//! 6 system_program
//! --- kind = 1 (token) only ---
//! 7 mint
//! 8 vault_ata         writable
//! 9 recipient_ata     writable   created if missing
//! 10 next_vault_ata   writable   created if missing
//! 11 token_program
//! 12 ata_program
//! 13.. extra accounts forwarded to both transfers (transfer hooks)
//! ```
//! Data: `kind (u8) ‖ amount (u64 LE) ‖ next_vault_hash (32)`

use crate::error::PqcVaultError;
use crate::message::{spend_digest, SOL_MINT};
use crate::state::{SigBuffer, Tombstone};
use crate::wots::recover_pk_hash;
use crate::{
    buffer_address, token, vault_address, KIND_SOL, KIND_TOKEN, VAULT_SEED, VAULT_VERSION,
};
use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;
use solana_program::rent::Rent;
use solana_program::sysvar::Sysvar;

const DATA_LEN: usize = 1 + 8 + 32;

struct TokenAccounts<'a, 'b> {
    mint: &'b AccountInfo<'a>,
    vault_ata: &'b AccountInfo<'a>,
    recipient_ata: &'b AccountInfo<'a>,
    next_vault_ata: &'b AccountInfo<'a>,
    token_program: &'b AccountInfo<'a>,
    ata_program: &'b AccountInfo<'a>,
    extra: &'b [AccountInfo<'a>],
}

pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != DATA_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let kind = data[0];
    let amount = u64::from_le_bytes(data[1..9].try_into().unwrap());
    let next_vault_hash = crate::read_hash(&data[9..41]);

    let iter = &mut accounts.iter();
    let payer = next_account_info(iter)?;
    let buffer = next_account_info(iter)?;
    let buffer_payer = next_account_info(iter)?;
    let vault = next_account_info(iter)?;
    let next_vault = next_account_info(iter)?;
    let recipient = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    crate::require_system_program(system_program)?;

    let tokens = match kind {
        KIND_SOL => None,
        KIND_TOKEN => {
            let mint = next_account_info(iter)?;
            let vault_ata = next_account_info(iter)?;
            let recipient_ata = next_account_info(iter)?;
            let next_vault_ata = next_account_info(iter)?;
            let token_program = next_account_info(iter)?;
            let ata_program = next_account_info(iter)?;
            Some(TokenAccounts {
                mint,
                vault_ata,
                recipient_ata,
                next_vault_ata,
                token_program,
                ata_program,
                extra: iter.as_slice(),
            })
        }
        _ => return Err(PqcVaultError::InvalidKind.into()),
    };
    let mint_key = tokens.as_ref().map_or(SOL_MINT, |t| *t.mint.key);

    // --- Vault and destination state. Cheap checks first. ---
    if vault.owner == program_id {
        return Err(PqcVaultError::VaultAlreadySpent.into());
    }
    if !crate::is_empty_system_account(vault) {
        return Err(PqcVaultError::UnexpectedVaultState.into());
    }
    if recipient.key == vault.key {
        return Err(PqcVaultError::RecipientIsVault.into());
    }
    let (expected_next, _) = vault_address(&next_vault_hash);
    if expected_next != *next_vault.key {
        return Err(PqcVaultError::InvalidNextVault.into());
    }
    if next_vault.key == vault.key {
        return Err(PqcVaultError::NextVaultIsSelf.into());
    }
    if next_vault.owner == program_id {
        return Err(PqcVaultError::NextVaultAlreadySpent.into());
    }
    if !crate::is_empty_system_account(next_vault) {
        return Err(PqcVaultError::InvalidNextVault.into());
    }

    // --- Bind the buffer to this exact message. ---
    let digest = spend_digest(
        program_id,
        vault.key,
        recipient.key,
        &mint_key,
        amount,
        &next_vault_hash,
    );
    SigBuffer::check(buffer, program_id)?;
    let staged_payer;
    let pk_hash;
    {
        let staged = buffer.try_borrow_data()?;
        staged_payer = SigBuffer::payer(&staged);
        if staged_payer != *buffer_payer.key {
            return Err(PqcVaultError::BufferPayerMismatch.into());
        }
        if SigBuffer::vault(&staged) != *vault.key {
            return Err(PqcVaultError::BufferVaultMismatch.into());
        }
        if SigBuffer::digest(&staged) != digest {
            return Err(PqcVaultError::BufferDigestMismatch.into());
        }
        let (expected_buffer, _) = buffer_address(vault.key, &digest, &staged_payer);
        if expected_buffer != *buffer.key {
            return Err(PqcVaultError::InvalidBuffer.into());
        }

        // --- The authority check: the signature must recover this vault's key. ---
        pk_hash = recover_pk_hash(
            &SigBuffer::pub_seed(&staged),
            SigBuffer::signature(&staged),
            &digest,
        )?;
    }
    let (expected_vault, bump) = vault_address(&pk_hash);
    if expected_vault != *vault.key {
        return Err(PqcVaultError::InvalidSignature.into());
    }
    let seeds: &[&[u8]] = &[VAULT_SEED, &[VAULT_VERSION], &pk_hash, &[bump]];

    // --- Tokens: amount to recipient, remainder to next_vault. ---
    if let Some(t) = &tokens {
        token::require_ata_program(t.ata_program)?;
        let decimals = token::mint_decimals(t.mint, t.token_program.key)?;
        token::require_ata(t.vault_ata, vault.key, t.token_program.key, t.mint.key)?;
        token::require_ata(
            t.recipient_ata,
            recipient.key,
            t.token_program.key,
            t.mint.key,
        )?;
        token::require_ata(
            t.next_vault_ata,
            next_vault.key,
            t.token_program.key,
            t.mint.key,
        )?;

        let balance = token::token_amount(t.vault_ata, t.token_program.key)?;
        if amount > balance {
            return Err(PqcVaultError::InsufficientFunds.into());
        }
        if amount > 0 {
            token::create_ata_idempotent(
                payer,
                t.recipient_ata,
                recipient,
                t.mint,
                system_program,
                t.token_program,
                t.ata_program,
            )?;
            token::transfer_checked_signed(
                t.token_program,
                t.vault_ata,
                t.mint,
                t.recipient_ata,
                vault,
                t.extra,
                amount,
                decimals,
                seeds,
            )?;
        }
        // Re-read: a transfer fee is withheld inside `amount`, so the source
        // is debited exactly `amount`, but trust the account rather than math.
        let remainder = token::token_amount(t.vault_ata, t.token_program.key)?;
        if remainder > 0 {
            token::create_ata_idempotent(
                payer,
                t.next_vault_ata,
                next_vault,
                t.mint,
                system_program,
                t.token_program,
                t.ata_program,
            )?;
            token::transfer_checked_signed(
                t.token_program,
                t.vault_ata,
                t.mint,
                t.next_vault_ata,
                vault,
                t.extra,
                remainder,
                decimals,
                seeds,
            )?;
        }
    }

    // --- Tombstone: the key is spent forever. ---
    let rent = Rent::get()?;
    crate::materialize_pda(payer, vault, system_program, Tombstone::LEN, seeds)?;
    Tombstone::write(
        &mut vault.try_borrow_mut_data()?,
        VAULT_VERSION,
        bump,
        &pk_hash,
        next_vault.key,
    );

    // --- SOL: amount to recipient, everything else to next_vault. ---
    let distributable = vault.lamports() - rent.minimum_balance(Tombstone::LEN);
    let to_recipient = if kind == KIND_SOL { amount } else { 0 };
    if to_recipient > distributable {
        return Err(PqcVaultError::InsufficientFunds.into());
    }
    let to_next = distributable - to_recipient;
    crate::debit(vault, distributable)?;
    if to_recipient > 0 {
        crate::credit(recipient, to_recipient)?;
        crate::require_rent_exempt(recipient, &rent)?;
    }
    if to_next > 0 {
        crate::credit(next_vault, to_next)?;
    }
    crate::require_rent_exempt(next_vault, &rent)?;

    // --- Done with the signature. ---
    crate::close_account(buffer, buffer_payer)
}
