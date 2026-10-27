//! Writes web/test/fixtures.json for the WASM test: a seeded v2 manifest
//! (endorsed by a throwaway 2-of-3 committee) and two testnet UAs, one
//! Orchard-only and one that also carries a transparent receiver.
//! Everything in it is public test data; no secret is written.
//!
//!   cargo run -p tally-wasm --example web_test_fixtures

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tally_crypto::manifest::{Committee, Manifest, MANIFEST_V2};
use tally_crypto::schnorr::Signature;
use tally_crypto::{dkg, g, random_scalar, Scalar};
use zcash_address::unified::{Address, Encoding, Receiver, Revision, Uitem};
use zcash_protocol::consensus::NetworkType;

fn ua(r: Vec<Receiver>) -> String {
    Address::try_from_items(Revision::R0, r.into_iter().map(Uitem::Data).collect()).unwrap().encode(&NetworkType::Test)
}

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(2026);
    let dealings: Vec<_> = (1..=3).map(|i| dkg::deal(i, 3, 2, &mut rng).unwrap()).collect();
    let key = dkg::committee_key(3, 2, &dealings.iter().map(|d| d.commitments.clone()).collect::<Vec<_>>()).unwrap();
    let xs: Vec<Scalar> = (1..=3u32)
        .map(|j| {
            let rec: Vec<_> = dealings.iter().map(|d| (d.dealer, d.commitments.as_slice(), d.shares[j as usize - 1])).collect();
            dkg::member_secret(j, &rec).unwrap()
        })
        .collect();
    let seller_sk = random_scalar(&mut rng);
    let mut m = Manifest {
        v: MANIFEST_V2,
        title: String::new(),
        auction_id: [0; 32],
        collection_id: [2; 32],
        supply: 2,
        ladder_zat: (1..=16u64).map(|i| i * 100_000).collect(),
        bond_zat: 100_000,
        open_height: 100,
        close_height: 200,
        settle_window_blocks: 100,
        min_batch: 5,
        committee: Committee { key, members: vec!["a".into(), "b".into(), "c".into()] },
        escrow_ua: ua(vec![Receiver::Orchard([3; 43])]),
        forfeit_ua: ua(vec![Receiver::Orchard([4; 43])]),
        seller_pk: g() * seller_sk,
        sig: Signature { r: g(), s: Scalar::from(0u64) },
        endorsements: vec![],
    };
    m.bind_id();
    m.sign(&seller_sk, &mut rng);
    m.endorsements = (1..=3u32).map(|j| m.endorse(j, &xs[j as usize - 1], &mut rng)).collect();
    m.verify_current().unwrap();
    let out = serde_json::json!({
        "manifest_v2": m,
        "orchard_only_ua": ua(vec![Receiver::Orchard([7; 43])]),
        "with_transparent_ua": ua(vec![Receiver::Orchard([7; 43]), Receiver::P2pkh([9; 20])]),
    });
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/test/fixtures.json");
    std::fs::write(path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    println!("wrote web/test/fixtures.json (auction {})", hex::encode(m.auction_id));
}
