//! The signed message. Rebuilt on-chain from the instruction's parameters; the
//! program never trusts a digest it is handed.

use solana_program::hash::hashv;
use solana_program::pubkey::Pubkey;

/// Domain separator. Bumping the version string invalidates every old message.
pub const SPEND_DOMAIN: &[u8] = b"pqc.market/vault-spend/v1";

/// Stands in for the mint when SOL is spent. No mint can exist at this key.
pub const SOL_MINT: Pubkey = Pubkey::new_from_array([0u8; 32]);

/// `SHA-256(domain ‖ program_id ‖ vault ‖ recipient ‖ mint-or-SOL ‖ amount_le ‖ next_vault_hash)`.
///
/// Every field that could let a signature be reused somewhere else is bound:
/// the program (and its version, via the domain), the vault, the destination,
/// the asset, the amount and the vault the remainder rolls into.
pub fn spend_digest(
    program_id: &Pubkey,
    vault: &Pubkey,
    recipient: &Pubkey,
    mint: &Pubkey,
    amount: u64,
    next_vault_hash: &[u8; 32],
) -> [u8; 32] {
    hashv(&[
        SPEND_DOMAIN,
        program_id.as_ref(),
        vault.as_ref(),
        recipient.as_ref(),
        mint.as_ref(),
        &amount.to_le_bytes(),
        next_vault_hash,
    ])
    .to_bytes()
}
