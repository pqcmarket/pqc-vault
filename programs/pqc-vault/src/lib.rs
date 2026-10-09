//! pqc-vault: Solana vaults that only a post-quantum (WOTS, hash-based)
//! signature can move. No ed25519 key has any authority over vault funds.
//!
//! A vault is a PDA at `["vault", version, SHA-256(wots_public_key)]`. Anyone
//! can deposit SOL or tokens to it. Spending takes a WOTS signature over a
//! message that binds every parameter; the program recovers the public key from
//! the signature, re-derives the vault address, pays `amount` to `recipient`,
//! rolls everything else into `next_vault`, and turns the spent vault into a
//! tombstone so the one-time key is never used twice.
//!
//! Instructions (first byte of data):
//! - `0` WriteSignature: stage a chunk of `pubSeed ‖ signature` in a buffer PDA.
//! - `1` Withdraw: verify, pay, roll the remainder, tombstone, close buffer.
//! - `2` CloseBuffer: abandon a staged signature and reclaim the rent.
//! - `3` Sweep: forward late deposits from a tombstone to its recorded `next_vault`.

pub mod error;
pub mod message;
pub mod state;
pub mod token;
pub mod wots;

mod close_buffer;
mod sweep;
mod withdraw;
mod write_signature;

use solana_program::account_info::AccountInfo;
use solana_program::entrypoint::ProgramResult;
use solana_program::program::{invoke, invoke_signed};
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;
use solana_program::rent::Rent;
use solana_program::sysvar::Sysvar;
// The 2.x SDK deprecates these in favour of crates that need a newer compiler
// than the SBF target has; they are stable and correct.
#[allow(deprecated)]
use solana_program::{system_instruction, system_program};

use crate::error::PqcVaultError;

solana_program::declare_id!("DNsPfPecrbnS7jFqMpEDG3VoWAdkuaU2VxsmaPENcg9F");

pub const VAULT_SEED: &[u8] = b"vault";
/// Vault address version. A new version means new addresses for every key.
pub const VAULT_VERSION: u8 = 1;
pub const SIG_SEED: &[u8] = b"sig";

pub const IX_WRITE_SIGNATURE: u8 = 0;
pub const IX_WITHDRAW: u8 = 1;
pub const IX_CLOSE_BUFFER: u8 = 2;
pub const IX_SWEEP: u8 = 3;

/// Spend kinds, the byte after the instruction tag in Withdraw and Sweep.
pub const KIND_SOL: u8 = 0;
pub const KIND_TOKEN: u8 = 1;

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if program_id != &ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (tag, rest) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match *tag {
        IX_WRITE_SIGNATURE => write_signature::process(program_id, accounts, rest),
        IX_WITHDRAW => withdraw::process(program_id, accounts, rest),
        IX_CLOSE_BUFFER => close_buffer::process(program_id, accounts, rest),
        IX_SWEEP => sweep::process(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// `["vault", version, pk_hash]`.
pub fn vault_address(pk_hash: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[VAULT_SEED, &[VAULT_VERSION], pk_hash], &ID)
}

/// `["sig", vault, digest, payer]`. Binding the payer stops anyone from
/// squatting a buffer address they saw in the mempool.
pub fn buffer_address(vault: &Pubkey, digest: &[u8; 32], payer: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SIG_SEED, vault.as_ref(), digest, payer.as_ref()], &ID)
}

/// Turns a PDA into a rent-exempt, program-owned account of `space` bytes,
/// whether it does not exist yet or is a system account someone already sent
/// lamports to (so a stray deposit can never block the flow).
pub(crate) fn materialize_pda<'a>(
    payer: &AccountInfo<'a>,
    account: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    space: usize,
    seeds: &[&[u8]],
) -> ProgramResult {
    let rent = Rent::get()?.minimum_balance(space);
    let lamports = account.lamports();
    if lamports < rent {
        invoke(
            &system_instruction::transfer(payer.key, account.key, rent - lamports),
            &[payer.clone(), account.clone(), system_program.clone()],
        )?;
    }
    invoke_signed(
        &system_instruction::allocate(account.key, space as u64),
        &[account.clone(), system_program.clone()],
        &[seeds],
    )?;
    invoke_signed(
        &system_instruction::assign(account.key, &ID),
        &[account.clone(), system_program.clone()],
        &[seeds],
    )
}

/// Moves every lamport out of a program-owned account and returns it to the
/// system program with no data, so it cannot be revived as ours.
pub(crate) fn close_account(account: &AccountInfo, destination: &AccountInfo) -> ProgramResult {
    let lamports = account.lamports();
    **account.try_borrow_mut_lamports()? = 0;
    credit(destination, lamports)?;
    account.resize(0)?;
    account.assign(&system_program::ID);
    Ok(())
}

pub(crate) fn credit(account: &AccountInfo, lamports: u64) -> ProgramResult {
    let mut balance = account.try_borrow_mut_lamports()?;
    **balance = balance
        .checked_add(lamports)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    Ok(())
}

pub(crate) fn debit(account: &AccountInfo, lamports: u64) -> ProgramResult {
    let mut balance = account.try_borrow_mut_lamports()?;
    **balance = balance
        .checked_sub(lamports)
        .ok_or(PqcVaultError::InsufficientFunds)?;
    Ok(())
}

/// The runtime rejects a transaction that leaves an account rent-paying. This
/// turns that into a named error before any state changes are wasted.
pub(crate) fn require_rent_exempt(account: &AccountInfo, rent: &Rent) -> ProgramResult {
    if account.lamports() == 0 || rent.is_exempt(account.lamports(), account.data_len()) {
        Ok(())
    } else {
        Err(PqcVaultError::BelowRentExemption.into())
    }
}

pub(crate) fn require_system_program(info: &AccountInfo) -> ProgramResult {
    if system_program::check_id(info.key) {
        Ok(())
    } else {
        Err(PqcVaultError::InvalidSystemProgram.into())
    }
}

/// An account that exists only as a plain system account (or not at all).
pub(crate) fn is_empty_system_account(info: &AccountInfo) -> bool {
    system_program::check_id(info.owner) && info.data_len() == 0
}

pub(crate) fn read_pubkey(bytes: &[u8]) -> Pubkey {
    Pubkey::new_from_array(bytes.try_into().unwrap())
}

pub(crate) fn read_hash(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().unwrap()
}
