//! Error codes. Numbers start at 6000 and are stable: the client maps them.

use solana_program::program_error::ProgramError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PqcVaultError {
    /// The WOTS signature does not recover the key this vault commits to.
    InvalidSignature = 6000,
    /// The vault already spent once. Its remainder lives in `next_vault`.
    VaultAlreadySpent = 6001,
    /// The vault account is neither empty nor one of ours.
    UnexpectedVaultState = 6002,
    /// The signature buffer is missing, foreign, or malformed.
    InvalidBuffer = 6003,
    /// The buffer was written for a different message.
    BufferDigestMismatch = 6004,
    /// The buffer was written for a different vault.
    BufferVaultMismatch = 6005,
    /// Only the account that funded a buffer may write to or close it.
    BufferPayerMismatch = 6006,
    /// A signature chunk falls outside the buffer.
    WriteOutOfBounds = 6007,
    /// `next_vault` is not the vault derived from `next_vault_hash`, or is not
    /// an empty system account.
    InvalidNextVault = 6008,
    /// A vault cannot roll into itself.
    NextVaultIsSelf = 6009,
    /// `next_vault` already spent; funds sent there could only be swept onward.
    NextVaultAlreadySpent = 6010,
    /// The recipient cannot be the vault being spent.
    RecipientIsVault = 6011,
    /// The vault holds less than `amount` plus what the tombstone needs.
    InsufficientFunds = 6012,
    /// A credited account would be left below rent exemption.
    BelowRentExemption = 6013,
    /// Not SPL Token or Token-2022, or not the mint's owner.
    InvalidTokenProgram = 6014,
    /// The mint account is malformed.
    InvalidMint = 6015,
    /// A token account is not the expected associated token account.
    InvalidTokenAccount = 6016,
    /// Not the Associated Token Account program.
    InvalidAssociatedTokenProgram = 6017,
    /// Not the System program.
    InvalidSystemProgram = 6018,
    /// Sweep needs a spent vault.
    NotATombstone = 6019,
    /// The spend kind byte must be 0 (SOL) or 1 (token).
    InvalidKind = 6020,
}

impl From<PqcVaultError> for ProgramError {
    fn from(e: PqcVaultError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
