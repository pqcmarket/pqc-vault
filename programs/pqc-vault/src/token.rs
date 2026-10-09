//! Hand-built SPL Token / Token-2022 / Associated Token Account CPIs. The two
//! token programs share the instruction encodings and base layouts used here,
//! and a mint's owner decides which one is invoked.

use crate::error::PqcVaultError;
use solana_program::account_info::AccountInfo;
use solana_program::entrypoint::ProgramResult;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_program::program::{invoke, invoke_signed};
use solana_program::program_error::ProgramError;
use solana_program::pubkey::{pubkey, Pubkey};

pub const TOKEN_PROGRAM_ID: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const TOKEN_2022_PROGRAM_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const ATA_PROGRAM_ID: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

const MINT_BASE_LEN: usize = 82;
const MINT_DECIMALS: usize = 44;
const MINT_INITIALIZED: usize = 45;
const ACCOUNT_BASE_LEN: usize = 165;
const ACCOUNT_AMOUNT: usize = 64;

const IX_TRANSFER_CHECKED: u8 = 12;
const IX_CLOSE_ACCOUNT: u8 = 9;
const IX_ATA_CREATE_IDEMPOTENT: u8 = 1;

pub fn is_token_program(key: &Pubkey) -> bool {
    *key == TOKEN_PROGRAM_ID || *key == TOKEN_2022_PROGRAM_ID
}

pub fn associated_token_address(owner: &Pubkey, token_program: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ATA_PROGRAM_ID,
    )
    .0
}

/// Validates `token_program` and that it owns `mint`; returns the decimals.
pub fn mint_decimals(mint: &AccountInfo, token_program: &Pubkey) -> Result<u8, ProgramError> {
    if !is_token_program(token_program) || mint.owner != token_program {
        return Err(PqcVaultError::InvalidTokenProgram.into());
    }
    let data = mint.try_borrow_data()?;
    if data.len() < MINT_BASE_LEN || data[MINT_INITIALIZED] != 1 {
        return Err(PqcVaultError::InvalidMint.into());
    }
    Ok(data[MINT_DECIMALS])
}

/// Balance of an existing token account owned by `token_program`.
pub fn token_amount(account: &AccountInfo, token_program: &Pubkey) -> Result<u64, ProgramError> {
    if account.owner != token_program {
        return Err(PqcVaultError::InvalidTokenAccount.into());
    }
    let data = account.try_borrow_data()?;
    if data.len() < ACCOUNT_BASE_LEN {
        return Err(PqcVaultError::InvalidTokenAccount.into());
    }
    Ok(u64::from_le_bytes(
        data[ACCOUNT_AMOUNT..ACCOUNT_AMOUNT + 8].try_into().unwrap(),
    ))
}

/// Requires `ata` to be the associated token account of `owner` for `mint`.
pub fn require_ata(
    ata: &AccountInfo,
    owner: &Pubkey,
    token_program: &Pubkey,
    mint: &Pubkey,
) -> ProgramResult {
    if *ata.key == associated_token_address(owner, token_program, mint) {
        Ok(())
    } else {
        Err(PqcVaultError::InvalidTokenAccount.into())
    }
}

pub fn require_ata_program(info: &AccountInfo) -> ProgramResult {
    if *info.key == ATA_PROGRAM_ID {
        Ok(())
    } else {
        Err(PqcVaultError::InvalidAssociatedTokenProgram.into())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn create_ata_idempotent<'a>(
    payer: &AccountInfo<'a>,
    ata: &AccountInfo<'a>,
    owner: &AccountInfo<'a>,
    mint: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    token_program: &AccountInfo<'a>,
    ata_program: &AccountInfo<'a>,
) -> ProgramResult {
    let ix = Instruction {
        program_id: ATA_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer.key, true),
            AccountMeta::new(*ata.key, false),
            AccountMeta::new_readonly(*owner.key, false),
            AccountMeta::new_readonly(*mint.key, false),
            AccountMeta::new_readonly(*system_program.key, false),
            AccountMeta::new_readonly(*token_program.key, false),
        ],
        data: vec![IX_ATA_CREATE_IDEMPOTENT],
    };
    invoke(
        &ix,
        &[
            payer.clone(),
            ata.clone(),
            owner.clone(),
            mint.clone(),
            system_program.clone(),
            token_program.clone(),
            ata_program.clone(),
        ],
    )
}

/// `TransferChecked` signed by a PDA. `extra` is forwarded verbatim so
/// Token-2022 transfer hooks get the accounts the caller resolved for them.
#[allow(clippy::too_many_arguments)]
pub fn transfer_checked_signed<'a>(
    token_program: &AccountInfo<'a>,
    source: &AccountInfo<'a>,
    mint: &AccountInfo<'a>,
    destination: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    extra: &[AccountInfo<'a>],
    amount: u64,
    decimals: u8,
    seeds: &[&[u8]],
) -> ProgramResult {
    let mut accounts = Vec::with_capacity(4 + extra.len());
    accounts.push(AccountMeta::new(*source.key, false));
    accounts.push(AccountMeta::new_readonly(*mint.key, false));
    accounts.push(AccountMeta::new(*destination.key, false));
    accounts.push(AccountMeta::new_readonly(*authority.key, true));
    for info in extra {
        accounts.push(AccountMeta {
            pubkey: *info.key,
            is_signer: info.is_signer,
            is_writable: info.is_writable,
        });
    }
    let mut data = Vec::with_capacity(10);
    data.push(IX_TRANSFER_CHECKED);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    let ix = Instruction {
        program_id: *token_program.key,
        accounts,
        data,
    };
    let mut infos = Vec::with_capacity(5 + extra.len());
    infos.extend_from_slice(&[
        source.clone(),
        mint.clone(),
        destination.clone(),
        authority.clone(),
    ]);
    infos.extend(extra.iter().cloned());
    infos.push(token_program.clone());
    invoke_signed(&ix, &infos, &[seeds])
}

/// `CloseAccount` signed by a PDA; the rent goes to `destination`.
pub fn close_account_signed<'a>(
    token_program: &AccountInfo<'a>,
    account: &AccountInfo<'a>,
    destination: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    seeds: &[&[u8]],
) -> ProgramResult {
    let ix = Instruction {
        program_id: *token_program.key,
        accounts: vec![
            AccountMeta::new(*account.key, false),
            AccountMeta::new(*destination.key, false),
            AccountMeta::new_readonly(*authority.key, true),
        ],
        data: vec![IX_CLOSE_ACCOUNT],
    };
    invoke_signed(
        &ix,
        &[
            account.clone(),
            destination.clone(),
            authority.clone(),
            token_program.clone(),
        ],
        &[seeds],
    )
}
