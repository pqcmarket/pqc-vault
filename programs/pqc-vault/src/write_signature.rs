//! WriteSignature: stage a chunk of `pubSeed ‖ signature` (2,176 bytes, more
//! than a transaction holds) in a buffer PDA bound to the vault, the message and
//! the payer. The first chunk creates the buffer.
//!
//! Accounts: `[payer (signer, writable), buffer (writable), system_program]`
//! Data: `vault (32) ‖ digest (32) ‖ offset (u16 LE) ‖ chunk`

use crate::error::PqcVaultError;
use crate::state::SigBuffer;
use crate::{buffer_address, materialize_pda, read_hash, read_pubkey, SIG_SEED};
use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;

const HEADER_LEN: usize = 32 + 32 + 2;

pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() <= HEADER_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let vault = read_pubkey(&data[0..32]);
    let digest = read_hash(&data[32..64]);
    let offset = usize::from(u16::from_le_bytes([data[64], data[65]]));
    let chunk = &data[HEADER_LEN..];

    let iter = &mut accounts.iter();
    let payer = next_account_info(iter)?;
    let buffer = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    crate::require_system_program(system_program)?;

    let (expected, bump) = buffer_address(&vault, &digest, payer.key);
    if expected != *buffer.key {
        return Err(PqcVaultError::InvalidBuffer.into());
    }
    let end = offset
        .checked_add(chunk.len())
        .ok_or(PqcVaultError::WriteOutOfBounds)?;
    if end > SigBuffer::PAYLOAD_LEN {
        return Err(PqcVaultError::WriteOutOfBounds.into());
    }

    if crate::is_empty_system_account(buffer) {
        materialize_pda(
            payer,
            buffer,
            system_program,
            SigBuffer::LEN,
            &[
                SIG_SEED,
                vault.as_ref(),
                digest.as_ref(),
                payer.key.as_ref(),
                &[bump],
            ],
        )?;
        SigBuffer::init(
            &mut buffer.try_borrow_mut_data()?,
            payer.key,
            &vault,
            &digest,
        );
    } else {
        SigBuffer::check(buffer, program_id)?;
        let existing = buffer.try_borrow_data()?;
        if SigBuffer::payer(&existing) != *payer.key {
            return Err(PqcVaultError::BufferPayerMismatch.into());
        }
        if SigBuffer::vault(&existing) != vault {
            return Err(PqcVaultError::BufferVaultMismatch.into());
        }
        if SigBuffer::digest(&existing) != digest {
            return Err(PqcVaultError::BufferDigestMismatch.into());
        }
    }

    let mut buf = buffer.try_borrow_mut_data()?;
    buf[SigBuffer::PAYLOAD + offset..SigBuffer::PAYLOAD + end].copy_from_slice(chunk);
    Ok(())
}
