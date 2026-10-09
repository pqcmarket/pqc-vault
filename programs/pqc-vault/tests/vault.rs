//! SOL spends end to end, and every way a spend must fail.

mod support;

use solana_keypair::Keypair;
use solana_signer::Signer;
use support::*;

const SOL: u64 = LAMPORTS_PER_SOL;

#[test]
fn full_cycle_deposit_withdraw_roll_then_spend_again() {
    let mut f = Fixture::new();
    let mut rng = Rng::new(1);
    let v0 = VaultKey::random(&mut rng);
    let v1 = VaultKey::random(&mut rng);
    let v2 = VaultKey::random(&mut rng);
    let recipient = Keypair::new().pubkey();

    // Deposit: a plain transfer to the address, nothing else.
    f.airdrop(&v0.address, 5 * SOL);
    let payer_before = f.balance(&f.payer_pubkey());

    let meta = f
        .spend_sol(&v0, &v1, &recipient, 2 * SOL)
        .expect("first spend");
    println!("SOL withdraw: {} CU", program_compute_units(&meta.logs));

    let tomb = f.tombstone_rent();
    assert_eq!(f.balance(&recipient), 2 * SOL);
    assert_eq!(f.balance(&v1.address), 5 * SOL - 2 * SOL - tomb);
    assert_eq!(f.balance(&v0.address), tomb);
    assert_eq!(f.owner(&v0.address), Some(program_id()));
    let data = f.data(&v0.address);
    assert_eq!(data.len(), 67);
    assert_eq!(data[0], 2);
    assert_eq!(data[1], 1);
    assert_eq!(data[2], v0.bump);
    assert_eq!(&data[3..35], &v0.pk_hash);
    assert_eq!(&data[35..67], v1.address.as_ref());

    // The buffer is gone and its rent came back: the payer only paid fees.
    let digest = digest_for(&v0.address, &recipient, None, 2 * SOL, &v1.pk_hash);
    let buffer = buffer_address(&v0.address, &digest, &f.payer_pubkey());
    assert_eq!(f.balance(&buffer), 0);
    assert!(f.svm.get_account(&buffer).is_none() || f.data(&buffer).is_empty());
    let spent_by_payer = payer_before - f.balance(&f.payer_pubkey());
    assert!(
        spent_by_payer < 50_000,
        "payer paid {spent_by_payer} lamports, expected fees only"
    );

    // The next vault is a normal vault: it spends the same way.
    let v1_balance = f.balance(&v1.address);
    f.spend_sol(&v1, &v2, &recipient, SOL)
        .expect("second spend");
    assert_eq!(f.balance(&recipient), 3 * SOL);
    assert_eq!(f.balance(&v2.address), v1_balance - SOL - tomb);
    assert_eq!(f.owner(&v1.address), Some(program_id()));
}

#[test]
fn zero_amount_rolls_everything_forward() {
    let mut f = Fixture::new();
    let mut rng = Rng::new(2);
    let v0 = VaultKey::random(&mut rng);
    let v1 = VaultKey::random(&mut rng);
    let recipient = Keypair::new().pubkey();
    f.airdrop(&v0.address, SOL);
    f.spend_sol(&v0, &v1, &recipient, 0).expect("roll");
    assert_eq!(f.balance(&recipient), 0);
    assert_eq!(f.balance(&v1.address), SOL - f.tombstone_rent());
}

#[test]
fn a_spent_vault_can_never_spend_again_and_late_deposits_sweep_forward() {
    let mut f = Fixture::new();
    let mut rng = Rng::new(3);
    let v0 = VaultKey::random(&mut rng);
    let v1 = VaultKey::random(&mut rng);
    let v2 = VaultKey::random(&mut rng);
    let recipient = Keypair::new().pubkey();
    f.airdrop(&v0.address, 2 * SOL);
    f.spend_sol(&v0, &v1, &recipient, SOL).expect("spend");

    // Someone deposits to the old address. A fresh, valid signature from the
    // same key is still refused: the key is spent.
    f.airdrop(&v0.address, 3 * SOL);
    assert_custom_error(
        f.spend_sol(&v0, &v2, &recipient, SOL),
        ERR_VAULT_ALREADY_SPENT,
    );

    // Sweep only goes where the spend already committed to.
    let ix = f.sweep_sol_ix(&v0.address, &v2.address);
    assert_custom_error(f.send_budgeted(&[ix]), ERR_INVALID_NEXT_VAULT);

    let v1_before = f.balance(&v1.address);
    let ix = f.sweep_sol_ix(&v0.address, &v1.address);
    f.send_budgeted(&[ix]).expect("sweep");
    assert_eq!(f.balance(&v1.address), v1_before + 3 * SOL);
    assert_eq!(f.balance(&v0.address), f.tombstone_rent());

    // Sweeping a vault that is not spent does nothing to it.
    let ix = f.sweep_sol_ix(&v1.address, &v2.address);
    assert_custom_error(f.send_budgeted(&[ix]), ERR_NOT_A_TOMBSTONE);
}

#[test]
fn tampered_signature_or_seed_is_rejected() {
    let mut f = Fixture::new();
    let mut rng = Rng::new(4);
    let v0 = VaultKey::random(&mut rng);
    let v1 = VaultKey::random(&mut rng);
    let recipient = Keypair::new().pubkey();
    f.airdrop(&v0.address, SOL);
    let digest = digest_for(&v0.address, &recipient, None, SOL / 2, &v1.pk_hash);
    let payer = f.payer_clone();

    for flip in [32usize, 32 + 1000, 32 + 2143, 5] {
        let mut payload = v0.payload(&digest);
        payload[flip] ^= 0x01;
        // Each attempt uses a different payer so the buffers do not collide.
        let staging_payer = Keypair::new();
        f.airdrop(&staging_payer.pubkey(), SOL);
        let buffer = f.stage(&staging_payer, &v0.address, &digest, &payload);
        let ix = f.withdraw_ix(
            &payer.pubkey(),
            &buffer,
            &staging_payer.pubkey(),
            &v0.address,
            &v1.address,
            &recipient,
            SOL / 2,
            &v1.pk_hash,
            None,
        );
        assert_custom_error(f.send_budgeted(&[ix]), ERR_INVALID_SIGNATURE);
    }
    assert_eq!(f.balance(&v0.address), SOL);
}

#[test]
fn a_signature_only_authorises_the_exact_message_it_signed() {
    let mut f = Fixture::new();
    let mut rng = Rng::new(5);
    let v0 = VaultKey::random(&mut rng);
    let v1 = VaultKey::random(&mut rng);
    let recipient = Keypair::new().pubkey();
    let thief = Keypair::new().pubkey();
    f.airdrop(&v0.address, SOL);
    let payer = f.payer_clone();

    let signed_amount = SOL / 4;
    let digest = digest_for(&v0.address, &recipient, None, signed_amount, &v1.pk_hash);
    let payload = v0.payload(&digest);
    let buffer = f.stage(&payer, &v0.address, &digest, &payload);

    // Same buffer, different amount: the buffer is bound to the digest.
    let ix = f.withdraw_ix(
        &payer.pubkey(),
        &buffer,
        &payer.pubkey(),
        &v0.address,
        &v1.address,
        &recipient,
        SOL / 2,
        &v1.pk_hash,
        None,
    );
    assert_custom_error(f.send_budgeted(&[ix]), ERR_BUFFER_DIGEST_MISMATCH);

    // Same buffer, different recipient.
    let ix = f.withdraw_ix(
        &payer.pubkey(),
        &buffer,
        &payer.pubkey(),
        &v0.address,
        &v1.address,
        &thief,
        signed_amount,
        &v1.pk_hash,
        None,
    );
    assert_custom_error(f.send_budgeted(&[ix]), ERR_BUFFER_DIGEST_MISMATCH);

    // Re-stage the stolen signature under the thief's message: it does not verify.
    let thief_digest = digest_for(&v0.address, &thief, None, signed_amount, &v1.pk_hash);
    let thief_buffer = f.stage(&payer, &v0.address, &thief_digest, &payload);
    let ix = f.withdraw_ix(
        &payer.pubkey(),
        &thief_buffer,
        &payer.pubkey(),
        &v0.address,
        &v1.address,
        &thief,
        signed_amount,
        &v1.pk_hash,
        None,
    );
    assert_custom_error(f.send_budgeted(&[ix]), ERR_INVALID_SIGNATURE);

    // A different next vault than the one signed over.
    let v9 = VaultKey::random(&mut rng);
    let ix = f.withdraw_ix(
        &payer.pubkey(),
        &buffer,
        &payer.pubkey(),
        &v0.address,
        &v9.address,
        &recipient,
        signed_amount,
        &v9.pk_hash,
        None,
    );
    assert_custom_error(f.send_budgeted(&[ix]), ERR_BUFFER_DIGEST_MISMATCH);

    // next_vault account that is not the PDA of next_vault_hash.
    let ix = f.withdraw_ix(
        &payer.pubkey(),
        &buffer,
        &payer.pubkey(),
        &v0.address,
        &v9.address,
        &recipient,
        signed_amount,
        &v1.pk_hash,
        None,
    );
    assert_custom_error(f.send_budgeted(&[ix]), ERR_INVALID_NEXT_VAULT);

    // The genuine message still goes through afterwards.
    let ix = f.withdraw_ix(
        &payer.pubkey(),
        &buffer,
        &payer.pubkey(),
        &v0.address,
        &v1.address,
        &recipient,
        signed_amount,
        &v1.pk_hash,
        None,
    );
    f.send_budgeted(&[ix]).expect("genuine spend");
    assert_eq!(f.balance(&recipient), signed_amount);
}

#[test]
fn next_vault_rules() {
    let mut f = Fixture::new();
    let mut rng = Rng::new(6);
    let v0 = VaultKey::random(&mut rng);
    let v1 = VaultKey::random(&mut rng);
    let v2 = VaultKey::random(&mut rng);
    let recipient = Keypair::new().pubkey();
    f.airdrop(&v0.address, SOL);
    f.airdrop(&v2.address, SOL);

    // Into itself.
    assert_custom_error(
        f.spend_sol(&v0, &v0, &recipient, SOL / 2),
        ERR_NEXT_VAULT_IS_SELF,
    );

    // Into a spent vault.
    f.spend_sol(&v0, &v1, &recipient, SOL / 2).expect("spend");
    assert_custom_error(
        f.spend_sol(&v2, &v0, &recipient, SOL / 2),
        ERR_NEXT_VAULT_ALREADY_SPENT,
    );

    // Recipient cannot be the vault itself.
    let v3 = VaultKey::random(&mut rng);
    assert_custom_error(
        f.spend_sol(&v2, &v3, &v2.address, SOL / 2),
        ERR_RECIPIENT_IS_VAULT,
    );
}

#[test]
fn funds_and_rent_limits() {
    let mut f = Fixture::new();
    let mut rng = Rng::new(7);
    let v0 = VaultKey::random(&mut rng);
    let v1 = VaultKey::random(&mut rng);
    let recipient = Keypair::new().pubkey();
    f.airdrop(&v0.address, SOL);
    let tomb = f.tombstone_rent();

    // More than the vault holds (the tombstone keeps its own rent).
    assert_custom_error(
        f.spend_sol(&v0, &v1, &recipient, SOL - tomb + 1),
        ERR_INSUFFICIENT_FUNDS,
    );

    // A remainder of one lamport cannot open the next vault.
    assert_custom_error(
        f.spend_sol(&v0, &v1, &recipient, SOL - tomb - 1),
        ERR_BELOW_RENT_EXEMPTION,
    );

    // Dust to a brand-new recipient would be rejected by the runtime; the
    // program names it instead.
    assert_custom_error(
        f.spend_sol(&v0, &v1, &recipient, 1_000),
        ERR_BELOW_RENT_EXEMPTION,
    );

    // Exactly everything is fine: remainder zero, no next vault account created.
    f.spend_sol(&v0, &v1, &recipient, SOL - tomb)
        .expect("spend all");
    assert_eq!(f.balance(&recipient), SOL - tomb);
    assert_eq!(f.balance(&v1.address), 0);
}

#[test]
fn buffers_belong_to_their_payer() {
    let mut f = Fixture::new();
    let mut rng = Rng::new(8);
    let v0 = VaultKey::random(&mut rng);
    let v1 = VaultKey::random(&mut rng);
    let recipient = Keypair::new().pubkey();
    f.airdrop(&v0.address, SOL);
    let digest = digest_for(&v0.address, &recipient, None, SOL / 2, &v1.pk_hash);
    let payload = v0.payload(&digest);

    let alice = Keypair::new();
    let mallory = Keypair::new();
    f.airdrop(&alice.pubkey(), SOL);
    f.airdrop(&mallory.pubkey(), SOL);
    let fee_payer = f.payer_clone();

    let alice_buffer = f.stage(&alice, &v0.address, &digest, &payload);
    assert_eq!(f.balance(&alice.pubkey()), SOL - f.buffer_rent());

    // Mallory cannot write into Alice's buffer: the address is derived from the
    // signer, so hers is a different account.
    let mut ix = f.write_ix(&mallory.pubkey(), &v0.address, &digest, 0, &[0u8; 100]);
    ix.accounts[1].pubkey = alice_buffer;
    assert_custom_error(f.send(&[ix], &[&fee_payer, &mallory]), ERR_INVALID_BUFFER);

    // Nor close it.
    let ix = f.close_buffer_ix(&mallory.pubkey(), &alice_buffer);
    assert_custom_error(
        f.send(&[ix], &[&fee_payer, &mallory]),
        ERR_BUFFER_PAYER_MISMATCH,
    );

    // A chunk past the end is refused.
    let ix = f.write_ix(&alice.pubkey(), &v0.address, &digest, 2000, &[0u8; 200]);
    assert_custom_error(
        f.send(&[ix], &[&fee_payer, &alice]),
        ERR_WRITE_OUT_OF_BOUNDS,
    );

    // Anyone may submit the withdraw once staged; the rent returns to Alice.
    let ix = f.withdraw_ix(
        &mallory.pubkey(),
        &alice_buffer,
        &alice.pubkey(),
        &v0.address,
        &v1.address,
        &recipient,
        SOL / 2,
        &v1.pk_hash,
        None,
    );
    f.send(&[ix], &[&fee_payer, &mallory])
        .expect("withdraw by a third party");
    assert_eq!(f.balance(&alice.pubkey()), SOL);
    assert_eq!(f.balance(&recipient), SOL / 2);

    // Alice can abandon a staged signature and get her rent back.
    let v2 = VaultKey::random(&mut rng);
    let digest2 = digest_for(&v1.address, &recipient, None, 1, &v2.pk_hash);
    let buffer2 = f.stage(&alice, &v1.address, &digest2, &v1.payload(&digest2));
    assert_eq!(f.balance(&alice.pubkey()), SOL - f.buffer_rent());
    let ix = f.close_buffer_ix(&alice.pubkey(), &buffer2);
    f.send(&[ix], &[&fee_payer, &alice]).expect("close buffer");
    assert_eq!(f.balance(&alice.pubkey()), SOL);
    assert_eq!(f.balance(&buffer2), 0);
}

#[test]
fn stray_lamports_at_buffer_or_vault_addresses_do_not_block_anything() {
    let mut f = Fixture::new();
    let mut rng = Rng::new(9);
    let v0 = VaultKey::random(&mut rng);
    let v1 = VaultKey::random(&mut rng);
    let recipient = Keypair::new().pubkey();
    f.airdrop(&v0.address, SOL);
    let digest = digest_for(&v0.address, &recipient, None, SOL / 2, &v1.pk_hash);
    let buffer = buffer_address(&v0.address, &digest, &f.payer_pubkey());
    // Above the rent floor (the runtime refuses less) but far below buffer rent.
    f.airdrop(&buffer, 1_000_000);

    let payer = f.payer_clone();
    let payer_before = f.balance(&payer.pubkey());
    f.stage(&payer, &v0.address, &digest, &v0.payload(&digest));
    let ix = f.withdraw_ix(
        &payer.pubkey(),
        &buffer,
        &payer.pubkey(),
        &v0.address,
        &v1.address,
        &recipient,
        SOL / 2,
        &v1.pk_hash,
        None,
    );
    f.send_budgeted(&[ix]).expect("spend");
    // The stray lamports came back with the buffer rent.
    assert!(f.balance(&payer.pubkey()) > payer_before);
}

#[test]
fn withdraw_without_a_staged_signature_fails() {
    let mut f = Fixture::new();
    let mut rng = Rng::new(10);
    let v0 = VaultKey::random(&mut rng);
    let v1 = VaultKey::random(&mut rng);
    let recipient = Keypair::new().pubkey();
    f.airdrop(&v0.address, SOL);
    let digest = digest_for(&v0.address, &recipient, None, SOL / 2, &v1.pk_hash);
    let payer = f.payer_pubkey();
    let buffer = buffer_address(&v0.address, &digest, &payer);
    let ix = f.withdraw_ix(
        &payer,
        &buffer,
        &payer,
        &v0.address,
        &v1.address,
        &recipient,
        SOL / 2,
        &v1.pk_hash,
        None,
    );
    assert_custom_error(f.send_budgeted(&[ix]), ERR_INVALID_BUFFER);

    // A partially written signature verifies as garbage, not as anything else.
    let payload = v0.payload(&digest);
    let ix = f.write_ix(&payer, &v0.address, &digest, 0, &payload[..CHUNK]);
    f.send_budgeted(&[ix]).expect("one chunk");
    let ix = f.withdraw_ix(
        &payer,
        &buffer,
        &payer,
        &v0.address,
        &v1.address,
        &recipient,
        SOL / 2,
        &v1.pk_hash,
        None,
    );
    assert_custom_error(f.send_budgeted(&[ix]), ERR_INVALID_SIGNATURE);
}
