//! Sweep: forward whatever reached a spent vault after its spend to the
//! `next_vault` its owner committed to. Permissionless: the destination is
//! fixed by the tombstone, so there is nothing a caller can redirect.
//!
//! Also the way a spend's leftover token account gets closed (its rent goes to
//! `next_vault`), kept out of Withdraw so a mint quirk (withheld transfer fees,
//! a strict hook) can never make a one-time signature's spend fail.
//!
//! Accounts:
//! ```text
//! 0 vault        writable   a tombstone
//! 1 next_vault   writable   the one recorded in the tombstone
//! 2 system_program
//! --- kind = 1 (token) only ---
//! 3 payer            signer, writable   funds next_vault's ATA if missing
//! 4 mint
//! 5 vault_ata        writable
//! 6 next_vault_ata   writable
//! 7 token_program
//! 8 ata_program
//! 9.. extra accounts forwarded to the transfer (transfer hooks)
//! ```
//! Data: `kind (u8) ‖ close_ata (u8)`; `close_ata = 1` closes the emptied
//! vault token account to `next_vault`.

use crate::error::PqcVaultError;
use crate::state::Tombstone;
use crate::{token, KIND_SOL, KIND_TOKEN, VAULT_SEED};
use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;
use solana_program::rent::Rent;
use solana_program::sysvar::Sysvar;

pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let kind = data[0];
    let close_ata = data[1] != 0;

    let iter = &mut accounts.iter();
    let vault = next_account_info(iter)?;
    let next_vault = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;
    crate::require_system_program(system_program)?;

    Tombstone::check(vault, program_id)?;
    let (version, bump, pk_hash, recorded_next) = {
        let d = vault.try_borrow_data()?;
        (
            Tombstone::version(&d),
            Tombstone::bump(&d),
            Tombstone::pk_hash(&d),
            Tombstone::next_vault(&d),
        )
    };
    if recorded_next != *next_vault.key {
        return Err(PqcVaultError::InvalidNextVault.into());
    }
    let seeds: &[&[u8]] = &[VAULT_SEED, &[version], &pk_hash, &[bump]];

    match kind {
        KIND_SOL => {
            let rent = Rent::get()?;
            let excess = vault.lamports() - rent.minimum_balance(Tombstone::LEN);
            if excess > 0 {
                crate::debit(vault, excess)?;
                crate::credit(next_vault, excess)?;
                crate::require_rent_exempt(next_vault, &rent)?;
            }
            Ok(())
        }
        KIND_TOKEN => {
            let payer = next_account_info(iter)?;
            let mint = next_account_info(iter)?;
            let vault_ata = next_account_info(iter)?;
            let next_vault_ata = next_account_info(iter)?;
            let token_program = next_account_info(iter)?;
            let ata_program = next_account_info(iter)?;
            let extra = iter.as_slice();

            if !payer.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }
            token::require_ata_program(ata_program)?;
            let decimals = token::mint_decimals(mint, token_program.key)?;
            token::require_ata(vault_ata, vault.key, token_program.key, mint.key)?;
            token::require_ata(next_vault_ata, next_vault.key, token_program.key, mint.key)?;

            let balance = token::token_amount(vault_ata, token_program.key)?;
            if balance > 0 {
                token::create_ata_idempotent(
                    payer,
                    next_vault_ata,
                    next_vault,
                    mint,
                    system_program,
                    token_program,
                    ata_program,
                )?;
                token::transfer_checked_signed(
                    token_program,
                    vault_ata,
                    mint,
                    next_vault_ata,
                    vault,
                    extra,
                    balance,
                    decimals,
                    seeds,
                )?;
            }
            if close_ata {
                token::close_account_signed(token_program, vault_ata, next_vault, vault, seeds)?;
            }
            Ok(())
        }
        _ => Err(PqcVaultError::InvalidKind.into()),
    }
}
