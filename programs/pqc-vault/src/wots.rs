//! Winternitz one-time signatures (WOTS, w = 16) over SHA-256, exactly as the
//! pqc.market web app computes them.
//!
//! Parameters:
//! - n = 32 bytes, w = 16 → 64 message nibbles + 3 checksum nibbles = 67 chains.
//! - ADRS is 32 bytes: big-endian u32 `type | a | b | c` at offsets 0, 4, 8, 12,
//!   then 16 zero bytes. Types: 0 = chain step, 3 = secret PRF.
//! - Tweakable hash `F(pubSeed, ADRS, x) = SHA-256(pubSeed ‖ ADRS ‖ x)`.
//! - Secret element `sk_i = SHA-256(skSeed ‖ ADRS(3, leaf, i, 0))`.
//! - Chain step at position s: `x ← F(pubSeed, ADRS(0, leaf, i, s), x)`.
//! - `pk_i` = `sk_i` walked 15 steps (positions 0..=14). `σ_i` = `sk_i` walked
//!   `d_i` steps. Verify by walking `σ_i` from `d_i` up to 14.
//!
//! The on-chain verifier never receives the public key. It recovers every chain
//! end from the signature and hashes `pubSeed ‖ pk_0 ‖ … ‖ pk_66`; that hash is
//! the vault's identity (see [`crate::vault_address`]).

use solana_program::hash::hashv;
use solana_program::program_error::ProgramError;

/// Hash output length.
pub const N: usize = 32;
/// Nibbles of the 32-byte digest.
pub const LEN1: usize = 64;
/// Checksum nibbles.
pub const LEN2: usize = 3;
/// Chains per key.
pub const LEN: usize = LEN1 + LEN2;
/// Largest chain position: w − 1.
pub const W_MAX: u8 = 15;
/// A signature: 67 chain values.
pub const SIG_LEN: usize = LEN * N;
/// A public key as hashed into the vault address: `pubSeed ‖ pk_0 ‖ … ‖ pk_66`.
pub const PK_LEN: usize = N + LEN * N;

pub const ADRS_TYPE_CHAIN: u32 = 0;
pub const ADRS_TYPE_SECRET: u32 = 3;
/// Vault keys are single keys, not leaves of a tree. Their seeds are already
/// per-vault (HKDF over the vault index, see the client), so the leaf is fixed.
pub const LEAF: u32 = 0;

/// Writes `ADRS(type, a, b, c)` into `out`.
pub fn adrs(out: &mut [u8], adrs_type: u32, a: u32, b: u32, c: u32) {
    out[0..4].copy_from_slice(&adrs_type.to_be_bytes());
    out[4..8].copy_from_slice(&a.to_be_bytes());
    out[8..12].copy_from_slice(&b.to_be_bytes());
    out[12..16].copy_from_slice(&c.to_be_bytes());
    out[16..32].fill(0);
}

/// Base-16 digits of the digest followed by the three checksum digits. Each
/// value is the number of chain steps the signer took, so `15 − d_i` is what the
/// verifier still has to walk.
pub fn digest_to_steps(digest: &[u8; N]) -> [u8; LEN] {
    let mut steps = [0u8; LEN];
    let mut checksum: u32 = 0;
    for (j, byte) in digest.iter().enumerate() {
        let hi = byte >> 4;
        let lo = byte & 15;
        steps[2 * j] = hi;
        steps[2 * j + 1] = lo;
        checksum += u32::from(W_MAX - hi) + u32::from(W_MAX - lo);
    }
    steps[LEN1] = ((checksum >> 8) & 15) as u8;
    steps[LEN1 + 1] = ((checksum >> 4) & 15) as u8;
    steps[LEN1 + 2] = (checksum & 15) as u8;
    steps
}

/// One contiguous `pubSeed ‖ ADRS ‖ x` block so every chain step is a single
/// one-slice `sol_sha256` call.
struct Chain {
    buf: [u8; 3 * N],
}

impl Chain {
    const ADRS: usize = N;
    const STEP: usize = N + 12;
    const X: usize = 2 * N;

    fn new(pub_seed: &[u8; N]) -> Self {
        let mut buf = [0u8; 3 * N];
        buf[..N].copy_from_slice(pub_seed);
        Self { buf }
    }

    fn select(&mut self, chain: u32, x: &[u8]) {
        adrs(
            &mut self.buf[Self::ADRS..Self::X],
            ADRS_TYPE_CHAIN,
            LEAF,
            chain,
            0,
        );
        self.buf[Self::X..].copy_from_slice(x);
    }

    #[inline(always)]
    fn step(&mut self, position: u8) {
        self.buf[Self::STEP..Self::STEP + 4].copy_from_slice(&u32::from(position).to_be_bytes());
        let h = hashv(&[&self.buf]);
        self.buf[Self::X..].copy_from_slice(h.as_ref());
    }

    fn x(&self) -> &[u8] {
        &self.buf[Self::X..]
    }
}

/// Walks every chain of `signature` from its digest position up to 14 and
/// returns `SHA-256(pubSeed ‖ pk_0 ‖ … ‖ pk_66)`.
///
/// This is the whole verification: the result is compared against the hash the
/// vault address commits to. A wrong signature, digest or seed yields a
/// different hash, never an error, so callers must compare the output.
pub fn recover_pk_hash(
    pub_seed: &[u8; N],
    signature: &[u8],
    digest: &[u8; N],
) -> Result<[u8; N], ProgramError> {
    if signature.len() != SIG_LEN {
        return Err(ProgramError::InvalidArgument);
    }
    let steps = digest_to_steps(digest);
    let mut pk = Vec::with_capacity(PK_LEN);
    pk.extend_from_slice(pub_seed);
    let mut chain = Chain::new(pub_seed);
    for (i, start) in steps.iter().enumerate() {
        chain.select(i as u32, &signature[i * N..(i + 1) * N]);
        for position in *start..W_MAX {
            chain.step(position);
        }
        pk.extend_from_slice(chain.x());
    }
    Ok(hashv(&[&pk]).to_bytes())
}

/// Chain steps a verifier performs for `digest`: the figure compute cost scales
/// with. Worst case is 990 (an all-zero digest), best case 45.
pub fn verify_steps(digest: &[u8; N]) -> u32 {
    digest_to_steps(digest)
        .iter()
        .map(|d| u32::from(W_MAX - d))
        .sum()
}

/// Key generation and signing. Never compiled on-chain: the program only
/// verifies. Used by tests and to cross-check the TypeScript client's vectors.
#[cfg(not(target_os = "solana"))]
pub mod signer {
    use super::*;

    /// `sk_i = SHA-256(skSeed ‖ ADRS(3, leaf, i, 0))`.
    pub fn secret_element(sk_seed: &[u8; N], chain: u32) -> [u8; N] {
        let mut a = [0u8; N];
        adrs(&mut a, ADRS_TYPE_SECRET, LEAF, chain, 0);
        hashv(&[sk_seed, &a]).to_bytes()
    }

    /// `pubSeed ‖ pk_0 ‖ … ‖ pk_66`.
    pub fn public_key(sk_seed: &[u8; N], pub_seed: &[u8; N]) -> Vec<u8> {
        let mut pk = Vec::with_capacity(PK_LEN);
        pk.extend_from_slice(pub_seed);
        let mut chain = Chain::new(pub_seed);
        for i in 0..LEN {
            chain.select(i as u32, &secret_element(sk_seed, i as u32));
            for position in 0..W_MAX {
                chain.step(position);
            }
            pk.extend_from_slice(chain.x());
        }
        pk
    }

    /// What the vault address commits to.
    pub fn pk_hash(public_key: &[u8]) -> [u8; N] {
        hashv(&[public_key]).to_bytes()
    }

    pub fn sign(sk_seed: &[u8; N], pub_seed: &[u8; N], digest: &[u8; N]) -> Vec<u8> {
        let steps = digest_to_steps(digest);
        let mut sig = Vec::with_capacity(SIG_LEN);
        let mut chain = Chain::new(pub_seed);
        for (i, d) in steps.iter().enumerate() {
            chain.select(i as u32, &secret_element(sk_seed, i as u32));
            for position in 0..*d {
                chain.step(position);
            }
            sig.extend_from_slice(chain.x());
        }
        sig
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_split_bytes_high_nibble_first() {
        let mut digest = [0u8; 32];
        digest[0] = 0xA3;
        let steps = digest_to_steps(&digest);
        assert_eq!(steps[0], 0xA);
        assert_eq!(steps[1], 0x3);
        // checksum = (15-10) + (15-3) + 62*15 = 947 = 0x3B3
        assert_eq!(&steps[64..], &[3, 0xB, 3]);
    }

    #[test]
    fn worst_case_is_990_steps() {
        assert_eq!(verify_steps(&[0u8; 32]), 990);
        assert_eq!(verify_steps(&[0xFF; 32]), 45);
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let sk = [7u8; 32];
        let ps = [9u8; 32];
        let digest = [0x5Au8; 32];
        let pk = signer::public_key(&sk, &ps);
        let sig = signer::sign(&sk, &ps, &digest);
        assert_eq!(
            recover_pk_hash(&ps, &sig, &digest).unwrap(),
            signer::pk_hash(&pk)
        );
        let mut other = digest;
        other[31] ^= 1;
        assert_ne!(
            recover_pk_hash(&ps, &sig, &other).unwrap(),
            signer::pk_hash(&pk)
        );
    }
}
