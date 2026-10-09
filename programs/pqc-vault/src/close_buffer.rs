//! CloseBuffer: the payer abandons a staged signature and takes the rent back.
//! Withdraw closes the buffer itself, so this is only for aborted spends.
//!
//! Accounts: `[payer (signer, writable), buffer (writable)]`

use crate::error::PqcVaultError;
use crate::state::SigBuffer;
use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;

pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let iter = &mut accounts.iter();
    let payer = next_account_info(iter)?;
    let buffer = next_account_info(iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    SigBuffer::check(buffer, program_id)?;
    {
        let data = buffer.try_borrow_data()?;
        if SigBuffer::payer(&data) != *payer.key {
            return Err(PqcVaultError::BufferPayerMismatch.into());
        }
    }
    crate::close_account(buffer, payer)
}
