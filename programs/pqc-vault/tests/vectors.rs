//! The TypeScript client's vectors (vectors/*.json), checked by an independent
//! implementation: every byte of key generation, signing, derivation and
//! address computation, and finally the program accepting a payload the
//! TypeScript side signed.

mod support;

use hmac::{Hmac, Mac};
use pqc_vault::wots::{digest_to_steps, recover_pk_hash, signer, verify_steps};
use serde_json::Value;
use sha2::Sha256;
use solana_pubkey::Pubkey;
use std::str::FromStr;
use support::*;

fn load(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read {} ({e}); run `npm run vectors` in client/",
            path.display()
        )
    });
    serde_json::from_str(&text).unwrap()
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
    h(v).try_into().unwrap()
}

fn key(v: &Value) -> Pubkey {
    Pubkey::from_str(v.as_str().unwrap()).unwrap()
}

/// HKDF-SHA256 with an empty salt and a single output block.
fn hkdf32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut extract = Hmac::<Sha256>::new_from_slice(&[0u8; 32]).unwrap();
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();
    let mut expand = Hmac::<Sha256>::new_from_slice(&prk).unwrap();
    expand.update(info);
    expand.update(&[1u8]);
    expand.finalize().into_bytes().into()
}

#[test]
fn wots_vectors_match() {
    let doc = load("wots.json");
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 5);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let sk = h32(&case["skSeed"]);
        let ps = h32(&case["pubSeed"]);
        let digest = h32(&case["digest"]);

        let steps: Vec<u8> = case["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_u64().unwrap() as u8)
            .collect();
        assert_eq!(steps, digest_to_steps(&digest).to_vec(), "{name}: steps");
        assert_eq!(
            case["verifySteps"].as_u64().unwrap() as u32,
            verify_steps(&digest),
            "{name}: verifySteps"
        );

        assert_eq!(
            h32(&case["sk0"]),
            signer::secret_element(&sk, 0),
            "{name}: sk0"
        );
        assert_eq!(
            h32(&case["sk66"]),
            signer::secret_element(&sk, 66),
            "{name}: sk66"
        );

        let pk = signer::public_key(&sk, &ps);
        assert_eq!(h(&case["publicKey"]), pk, "{name}: publicKey");
        assert_eq!(h(&case["pk0"]), pk[32..64].to_vec(), "{name}: pk0");
        let pk_hash = signer::pk_hash(&pk);
        assert_eq!(
            h32(&case["publicKeyHash"]),
            pk_hash,
            "{name}: publicKeyHash"
        );

        let sig = signer::sign(&sk, &ps, &digest);
        assert_eq!(h(&case["signature"]), sig, "{name}: signature");
        assert_eq!(
            recover_pk_hash(&ps, &sig, &digest).unwrap(),
            pk_hash,
            "{name}: verify"
        );
    }
}

#[test]
fn vault_vectors_match_and_the_program_accepts_the_client_signature() {
    let doc = load("vault.json");
    assert_eq!(key(&doc["programId"]), program_id());
    assert_eq!(
        doc["vaultVersion"].as_u64().unwrap() as u8,
        pqc_vault::VAULT_VERSION
    );
    assert_eq!(
        doc["spendDomain"].as_str().unwrap().as_bytes(),
        pqc_vault::message::SPEND_DOMAIN
    );

    let id_sk = h32(&doc["identity"]["skSeed"]);
    let id_pub = h32(&doc["identity"]["pubSeed"]);
    let sk_prefix = doc["hkdf"]["skInfoPrefix"].as_str().unwrap().as_bytes();
    let pub_prefix = doc["hkdf"]["pubInfoPrefix"].as_str().unwrap().as_bytes();

    let mut keys = Vec::new();
    for v in doc["vaults"].as_array().unwrap() {
        let index = v["index"].as_u64().unwrap() as u32;
        let sk_info = [sk_prefix, &index.to_be_bytes()[..]].concat();
        let pub_info = [pub_prefix, &index.to_be_bytes()[..]].concat();
        let sk = hkdf32(&id_sk, &sk_info);
        let ps = hkdf32(&id_pub, &pub_info);
        assert_eq!(h32(&v["skSeed"]), sk, "vault {index}: skSeed");
        assert_eq!(h32(&v["pubSeed"]), ps, "vault {index}: pubSeed");
        let vk = VaultKey::from_seeds(sk, ps);
        assert_eq!(h32(&v["pkHash"]), vk.pk_hash, "vault {index}: pkHash");
        assert_eq!(key(&v["address"]), vk.address, "vault {index}: address");
        assert_eq!(
            v["bump"].as_u64().unwrap() as u8,
            vk.bump,
            "vault {index}: bump"
        );
        keys.push(vk);
    }
    let v0 = &keys[0];
    let v1 = &keys[1];

    for (name, mint) in [("solSpend", None), ("tokenSpend", Some(()))] {
        let case = &doc[name];
        let recipient = key(&case["recipient"]);
        let mint_key = mint.map(|_| key(&case["mint"]));
        let amount: u64 = case["amount"].as_str().unwrap().parse().unwrap();
        assert_eq!(key(&case["vault"]), v0.address);
        assert_eq!(key(&case["nextVault"]), v1.address);
        assert_eq!(h32(&case["nextVaultHash"]), v1.pk_hash);
        let digest = digest_for(
            &v0.address,
            &recipient,
            mint_key.as_ref(),
            amount,
            &v1.pk_hash,
        );
        assert_eq!(h32(&case["digest"]), digest, "{name}: digest");
        assert_eq!(
            case["verifySteps"].as_u64().unwrap() as u32,
            verify_steps(&digest)
        );
        let payer = key(&case["bufferPayer"]);
        assert_eq!(
            key(&case["buffer"]),
            buffer_address(&v0.address, &digest, &payer),
            "{name}: buffer"
        );
        assert_eq!(h(&case["payload"]), v0.payload(&digest), "{name}: payload");
    }

    // The program itself accepts the client-produced bytes, unmodified.
    let case = &doc["solSpend"];
    let recipient = key(&case["recipient"]);
    let amount: u64 = case["amount"].as_str().unwrap().parse().unwrap();
    let digest = h32(&case["digest"]);
    let payload = h(&case["payload"]);
    let mut f = Fixture::new();
    f.airdrop(&v0.address, 10 * LAMPORTS_PER_SOL);
    let payer = f.payer_clone();
    let buffer = f.stage(&payer, &v0.address, &digest, &payload);
    let ix = f.withdraw_ix(
        &payer.pubkey(),
        &buffer,
        &payer.pubkey(),
        &v0.address,
        &v1.address,
        &recipient,
        amount,
        &v1.pk_hash,
        None,
    );
    f.send_budgeted(&[ix])
        .expect("program accepts the TypeScript-signed spend");
    assert_eq!(f.balance(&recipient), amount);
    assert_eq!(f.owner(&v0.address), Some(program_id()));
}

use solana_signer::Signer;
