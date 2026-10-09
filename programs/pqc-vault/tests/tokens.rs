//! Token spends: Token-2022 (pump.fun coins) and classic SPL Token.

mod support;

use solana_keypair::Keypair;
use solana_signer::Signer;
use support::*;

const SOL: u64 = LAMPORTS_PER_SOL;
const UNITS: u64 = 1_000_000_000;

fn token(f: &mut Fixture, token_program: solana_pubkey::Pubkey) -> TokenSpend {
    let mint = f.create_mint(&token_program, 6);
    TokenSpend {
        mint,
        token_program,
        extra: vec![],
    }
}

fn cycle(token_program: solana_pubkey::Pubkey, seed: u64) {
    let mut f = Fixture::new();
    let mut rng = Rng::new(seed);
    let v0 = VaultKey::random(&mut rng);
    let v1 = VaultKey::random(&mut rng);
    let recipient = Keypair::new().pubkey();
    let t = token(&mut f, token_program);

    // Deposit tokens into the vault's ATA and some SOL into the vault.
    let vault_ata = f.mint_to(&t.token_program, &t.mint, &v0.address, UNITS);
    f.airdrop(&v0.address, SOL);

    let meta = f
        .spend_token(&v0, &v1, &recipient, &t, 300 * UNITS / 1000)
        .expect("token spend");
    println!(
        "token withdraw ({token_program}): {} CU",
        program_compute_units(&meta.logs)
    );

    assert_eq!(
        f.token_balance(&ata(&recipient, &t.token_program, &t.mint)),
        300 * UNITS / 1000
    );
    assert_eq!(
        f.token_balance(&ata(&v1.address, &t.token_program, &t.mint)),
        700 * UNITS / 1000
    );
    assert_eq!(f.token_balance(&vault_ata), 0);
    // SOL rolled too, and the vault is spent.
    assert_eq!(f.balance(&v1.address), SOL - f.tombstone_rent());
    assert_eq!(f.owner(&v0.address), Some(program_id()));

    // Cleanup: close the emptied vault ATA, its rent goes to the next vault.
    let v1_before = f.balance(&v1.address);
    let ata_rent = f.balance(&vault_ata);
    let ix = f.sweep_token_ix(&f.payer_pubkey(), &v0.address, &v1.address, &t, true);
    f.send_budgeted(&[ix]).expect("sweep + close");
    assert!(f.svm.get_account(&vault_ata).is_none() || f.data(&vault_ata).is_empty());
    assert_eq!(f.balance(&v1.address), v1_before + ata_rent);

    // A late token deposit to the spent vault sweeps forward (re-creates the ATA).
    f.mint_to(&t.token_program, &t.mint, &v0.address, 5 * UNITS);
    let ix = f.sweep_token_ix(&f.payer_pubkey(), &v0.address, &v1.address, &t, true);
    f.send_budgeted(&[ix]).expect("late sweep");
    assert_eq!(
        f.token_balance(&ata(&v1.address, &t.token_program, &t.mint)),
        700 * UNITS / 1000 + 5 * UNITS
    );

    // The old key is dead for tokens too.
    let v2 = VaultKey::random(&mut rng);
    f.mint_to(&t.token_program, &t.mint, &v0.address, UNITS);
    assert_custom_error(
        f.spend_token(&v0, &v2, &recipient, &t, 1),
        ERR_VAULT_ALREADY_SPENT,
    );
}

#[test]
fn token_2022_cycle() {
    cycle(token_2022(), 21);
}

#[test]
fn classic_spl_token_cycle() {
    cycle(token_classic(), 22);
}

#[test]
fn a_vault_holding_only_tokens_spends_with_the_payer_funding_the_tombstone() {
    let mut f = Fixture::new();
    let mut rng = Rng::new(23);
    let v0 = VaultKey::random(&mut rng);
    let v1 = VaultKey::random(&mut rng);
    let recipient = Keypair::new().pubkey();
    let t = token(&mut f, token_2022());
    f.mint_to(&t.token_program, &t.mint, &v0.address, UNITS);
    assert_eq!(f.balance(&v0.address), 0);

    f.spend_token(&v0, &v1, &recipient, &t, UNITS)
        .expect("spend");
    assert_eq!(
        f.token_balance(&ata(&recipient, &t.token_program, &t.mint)),
        UNITS
    );
    assert_eq!(f.balance(&v0.address), f.tombstone_rent());
    assert_eq!(f.owner(&v0.address), Some(program_id()));
    // Nothing went to the next vault, so no account was created there.
    assert_eq!(f.balance(&v1.address), 0);
}

#[test]
fn token_checks() {
    let mut f = Fixture::new();
    let mut rng = Rng::new(24);
    let v0 = VaultKey::random(&mut rng);
    let v1 = VaultKey::random(&mut rng);
    let recipient = Keypair::new().pubkey();
    let t = token(&mut f, token_2022());
    f.mint_to(&t.token_program, &t.mint, &v0.address, UNITS);
    f.airdrop(&v0.address, SOL);

    // More than the balance.
    assert_custom_error(
        f.spend_token(&v0, &v1, &recipient, &t, UNITS + 1),
        ERR_INSUFFICIENT_FUNDS,
    );

    // Wrong token program for the mint.
    let wrong = TokenSpend {
        mint: t.mint,
        token_program: token_classic(),
        extra: vec![],
    };
    assert_custom_error(
        f.spend_token(&v0, &v1, &recipient, &wrong, 1),
        ERR_INVALID_TOKEN_PROGRAM,
    );

    // A token account that is not the recipient's ATA.
    let amount = UNITS / 2;
    let digest = digest_for(&v0.address, &recipient, Some(&t.mint), amount, &v1.pk_hash);
    let payer = f.payer_clone();
    let buffer = f.stage(&payer, &v0.address, &digest, &v0.payload(&digest));
    let mallory = Keypair::new().pubkey();
    let mallory_ata = f.mint_to(&t.token_program, &t.mint, &mallory, 0);
    let mut ix = f.withdraw_ix(
        &payer.pubkey(),
        &buffer,
        &payer.pubkey(),
        &v0.address,
        &v1.address,
        &recipient,
        amount,
        &v1.pk_hash,
        Some(&t),
    );
    ix.accounts[9].pubkey = mallory_ata;
    assert_custom_error(f.send_budgeted(&[ix]), ERR_INVALID_TOKEN_ACCOUNT);

    // The next vault's ATA swapped for someone else's.
    let mut ix = f.withdraw_ix(
        &payer.pubkey(),
        &buffer,
        &payer.pubkey(),
        &v0.address,
        &v1.address,
        &recipient,
        amount,
        &v1.pk_hash,
        Some(&t),
    );
    ix.accounts[10].pubkey = mallory_ata;
    assert_custom_error(f.send_budgeted(&[ix]), ERR_INVALID_TOKEN_ACCOUNT);

    // A different mint than signed over.
    let other = token(&mut f, token_2022());
    f.mint_to(&other.token_program, &other.mint, &v0.address, UNITS);
    let mut ix = f.withdraw_ix(
        &payer.pubkey(),
        &buffer,
        &payer.pubkey(),
        &v0.address,
        &v1.address,
        &recipient,
        amount,
        &v1.pk_hash,
        Some(&other),
    );
    ix.accounts[1].pubkey = buffer;
    assert_custom_error(f.send_budgeted(&[ix]), ERR_BUFFER_DIGEST_MISMATCH);

    // The genuine one works.
    let ix = f.withdraw_ix(
        &payer.pubkey(),
        &buffer,
        &payer.pubkey(),
        &v0.address,
        &v1.address,
        &recipient,
        amount,
        &v1.pk_hash,
        Some(&t),
    );
    f.send_budgeted(&[ix]).expect("spend");
    assert_eq!(
        f.token_balance(&ata(&recipient, &t.token_program, &t.mint)),
        amount
    );

    // The other mint stayed behind at the tombstone; sweep forwards it.
    let ix = f.sweep_token_ix(&f.payer_pubkey(), &v0.address, &v1.address, &other, true);
    f.send_budgeted(&[ix]).expect("sweep other mint");
    assert_eq!(
        f.token_balance(&ata(&v1.address, &other.token_program, &other.mint)),
        UNITS
    );
}
