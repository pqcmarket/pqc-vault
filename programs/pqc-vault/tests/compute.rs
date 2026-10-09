//! Compute measurements. Verification cost is linear in the number of chain
//! steps the verifier walks (15 − d_i summed over 67 chains), so a few spends
//! with known step counts pin down the per-step price and the worst case
//! (990 steps, an all-zero digest) follows exactly.

mod support;

use pqc_vault::wots::verify_steps;
use solana_keypair::Keypair;
use solana_signer::Signer;
use support::*;

const SOL: u64 = LAMPORTS_PER_SOL;
const WORST_STEPS: f64 = 990.0;
/// Headroom for an unlucky bump search: three PDAs, each allowed ten failed
/// attempts at 1,500 CU. The odds of needing that are below 2^-30 per PDA.
const BUMP_MARGIN_CU: f64 = 3.0 * 10.0 * 1_500.0;
/// Hard ceiling asserted here; see README for the measured numbers.
const CEILING_CU: u64 = 400_000;

struct Sample {
    steps: u32,
    cu: u64,
}

fn fit(samples: &[Sample]) -> (f64, f64) {
    let n = samples.len() as f64;
    let mx = samples.iter().map(|s| s.steps as f64).sum::<f64>() / n;
    let my = samples.iter().map(|s| s.cu as f64).sum::<f64>() / n;
    let sxy: f64 = samples
        .iter()
        .map(|s| (s.steps as f64 - mx) * (s.cu as f64 - my))
        .sum();
    let sxx: f64 = samples.iter().map(|s| (s.steps as f64 - mx).powi(2)).sum();
    let slope = sxy / sxx;
    (my - slope * mx, slope)
}

/// Picks vault/recipient combinations whose digests span a wide range of
/// verification steps, so the fit covers more than the typical ~500.
fn spread_samples(f: &mut Fixture, rng: &mut Rng, count: usize) -> Vec<Sample> {
    let mut candidates: Vec<(u32, VaultKey, VaultKey, solana_pubkey::Pubkey)> = (0..150)
        .map(|_| {
            let v0 = VaultKey::random(rng);
            let v1 = VaultKey::random(rng);
            let recipient = Keypair::new().pubkey();
            let digest = digest_for(&v0.address, &recipient, None, SOL / 2, &v1.pk_hash);
            (verify_steps(&digest), v0, v1, recipient)
        })
        .collect();
    candidates.sort_by_key(|c| c.0);
    let stride = (candidates.len() - 1) / (count - 1);
    let mut samples = Vec::new();
    for idx in (0..candidates.len()).step_by(stride).take(count) {
        let (steps, v0, v1, recipient) = &candidates[idx];
        f.airdrop(&v0.address, SOL);
        let meta = f.spend_sol(v0, v1, recipient, SOL / 2).expect("spend");
        samples.push(Sample {
            steps: *steps,
            cu: program_compute_units(&meta.logs),
        });
    }
    samples
}

#[test]
fn verification_cost_and_worst_case() {
    let mut f = Fixture::new();
    let mut rng = Rng::new(99);
    let samples = spread_samples(&mut f, &mut rng, 6);
    for s in &samples {
        println!("SOL spend: {} steps -> {} CU", s.steps, s.cu);
    }
    let (fixed, per_step) = fit(&samples);
    let worst_sol = fixed + per_step * WORST_STEPS + BUMP_MARGIN_CU;
    println!("fit: fixed {fixed:.0} CU + {per_step:.1} CU/step");
    println!("worst-case SOL spend (990 steps): {worst_sol:.0} CU");

    // Residuals stay small: the only non-linear part is the bump search in the
    // three find_program_address calls (1,500 CU per failed attempt).
    for s in &samples {
        let predicted = fixed + per_step * s.steps as f64;
        let err = (predicted - s.cu as f64).abs();
        assert!(
            err < 15_000.0,
            "fit residual {err:.0} CU at {} steps",
            s.steps
        );
    }

    // Token-2022 adds the CPIs on top of the same verification.
    let v0 = VaultKey::random(&mut rng);
    let v1 = VaultKey::random(&mut rng);
    let recipient = Keypair::new().pubkey();
    let mint = f.create_mint(&token_2022(), 6);
    let t = TokenSpend {
        mint,
        token_program: token_2022(),
        extra: vec![],
    };
    f.mint_to(&t.token_program, &t.mint, &v0.address, 1_000_000);
    f.airdrop(&v0.address, SOL);
    let digest = digest_for(&v0.address, &recipient, Some(&t.mint), 400_000, &v1.pk_hash);
    let token_steps = verify_steps(&digest);
    let meta = f
        .spend_token(&v0, &v1, &recipient, &t, 400_000)
        .expect("token spend");
    let token_cu = program_compute_units(&meta.logs);
    let token_overhead = token_cu as f64 - (fixed + per_step * token_steps as f64);
    let worst_token = worst_sol + token_overhead;
    println!("Token-2022 spend: {token_steps} steps -> {token_cu} CU (CPI overhead {token_overhead:.0} CU)");
    println!("worst-case Token-2022 spend (990 steps): {worst_token:.0} CU");

    let report = format!(
        "{{\n  \"fixed_cu\": {fixed:.0},\n  \"cu_per_chain_step\": {per_step:.2},\n  \"worst_case_steps\": 990,\n  \"bump_search_margin_cu\": {BUMP_MARGIN_CU:.0},\n  \"worst_case_sol_withdraw_cu\": {worst_sol:.0},\n  \"token_2022_cpi_overhead_cu\": {token_overhead:.0},\n  \"worst_case_token_2022_withdraw_cu\": {worst_token:.0},\n  \"samples\": [{}]\n}}\n",
        samples
            .iter()
            .map(|s| format!("{{\"steps\": {}, \"cu\": {}}}", s.steps, s.cu))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/compute.json");
    std::fs::write(&out, report).expect("write compute report");

    assert!(
        worst_token < CEILING_CU as f64,
        "worst case {worst_token:.0} CU exceeds {CEILING_CU}"
    );
}
