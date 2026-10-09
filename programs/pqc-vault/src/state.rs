//! Account layouts. Both are plain byte layouts with a one-byte discriminator
//! so the client can read them without a codec.

use crate::error::PqcVaultError;
use crate::wots::{N, PK_LEN};
use solana_program::account_info::AccountInfo;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;

pub const BUFFER_DISCRIMINATOR: u8 = 1;
pub const TOMBSTONE_DISCRIMINATOR: u8 = 2;

/// Temporary home for a signature that does not fit in one transaction.
///
/// ```text
/// 0      discriminator = 1
/// 1..33  payer     funded the account, gets the rent back
/// 33..65 vault     the vault this signature spends
/// 65..97 digest    the message it signs
/// 97..   payload   pubSeed (32) ‖ signature (2144)
/// ```
pub struct SigBuffer;

impl SigBuffer {
    pub const PAYER: usize = 1;
    pub const VAULT: usize = 33;
    pub const DIGEST: usize = 65;
    pub const PAYLOAD: usize = 97;
    pub const PAYLOAD_LEN: usize = PK_LEN;
    pub const LEN: usize = Self::PAYLOAD + Self::PAYLOAD_LEN;

    pub fn init(data: &mut [u8], payer: &Pubkey, vault: &Pubkey, digest: &[u8; N]) {
        data[0] = BUFFER_DISCRIMINATOR;
        data[Self::PAYER..Self::VAULT].copy_from_slice(payer.as_ref());
        data[Self::VAULT..Self::DIGEST].copy_from_slice(vault.as_ref());
        data[Self::DIGEST..Self::PAYLOAD].copy_from_slice(digest);
    }

    /// Checks ownership, size and discriminator.
    pub fn check(info: &AccountInfo, program_id: &Pubkey) -> Result<(), ProgramError> {
        if info.owner != program_id {
            return Err(PqcVaultError::InvalidBuffer.into());
        }
        let data = info.try_borrow_data()?;
        if data.len() != Self::LEN || data[0] != BUFFER_DISCRIMINATOR {
            return Err(PqcVaultError::InvalidBuffer.into());
        }
        Ok(())
    }

    pub fn payer(data: &[u8]) -> Pubkey {
        Pubkey::new_from_array(data[Self::PAYER..Self::VAULT].try_into().unwrap())
    }

    pub fn vault(data: &[u8]) -> Pubkey {
        Pubkey::new_from_array(data[Self::VAULT..Self::DIGEST].try_into().unwrap())
    }

    pub fn digest(data: &[u8]) -> [u8; N] {
        data[Self::DIGEST..Self::PAYLOAD].try_into().unwrap()
    }

    pub fn pub_seed(data: &[u8]) -> [u8; N] {
        data[Self::PAYLOAD..Self::PAYLOAD + N].try_into().unwrap()
    }

    pub fn signature(data: &[u8]) -> &[u8] {
        &data[Self::PAYLOAD + N..Self::LEN]
    }
}

/// What a vault becomes after its one spend. The account keeps the PDA address
/// so the key can never be spent again, and records where the remainder went so
/// late deposits can be swept after it.
///
/// ```text
/// 0      discriminator = 2
/// 1      vault version
/// 2      bump
/// 3..35  pk_hash      SHA-256 of the WOTS public key (the vault seed)
/// 35..67 next_vault   where everything was rolled
/// ```
pub struct Tombstone;

impl Tombstone {
    pub const VERSION: usize = 1;
    pub const BUMP: usize = 2;
    pub const PK_HASH: usize = 3;
    pub const NEXT_VAULT: usize = 35;
    pub const LEN: usize = 67;

    pub fn write(data: &mut [u8], version: u8, bump: u8, pk_hash: &[u8; N], next_vault: &Pubkey) {
        data[0] = TOMBSTONE_DISCRIMINATOR;
        data[Self::VERSION] = version;
        data[Self::BUMP] = bump;
        data[Self::PK_HASH..Self::NEXT_VAULT].copy_from_slice(pk_hash);
        data[Self::NEXT_VAULT..Self::LEN].copy_from_slice(next_vault.as_ref());
    }

    pub fn check(info: &AccountInfo, program_id: &Pubkey) -> Result<(), ProgramError> {
        if info.owner != program_id {
            return Err(PqcVaultError::NotATombstone.into());
        }
        let data = info.try_borrow_data()?;
        if data.len() != Self::LEN || data[0] != TOMBSTONE_DISCRIMINATOR {
            return Err(PqcVaultError::NotATombstone.into());
        }
        Ok(())
    }

    pub fn version(data: &[u8]) -> u8 {
        data[Self::VERSION]
    }

    pub fn bump(data: &[u8]) -> u8 {
        data[Self::BUMP]
    }

    pub fn pk_hash(data: &[u8]) -> [u8; N] {
        data[Self::PK_HASH..Self::NEXT_VAULT].try_into().unwrap()
    }

    pub fn next_vault(data: &[u8]) -> Pubkey {
        Pubkey::new_from_array(data[Self::NEXT_VAULT..Self::LEN].try_into().unwrap())
    }
}
