//! Layer 2 acceptance: honest ballots verify; adversarial ballots don't.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tally_crypto::ballot::Ballot;
use tally_crypto::elgamal::Ciphertext;
use tally_crypto::{g, random_scalar, Error, Point};

const L: usize = 16;
const AUCTION: [u8; 32] = [7u8; 32];

fn setup() -> (ChaCha20Rng, Point) {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let h = g() * random_scalar(&mut rng);
    (rng, h)
}

fn values(ones: usize) -> Vec<u64> {
    (0..L).map(|i| (i < ones) as u64).collect()
}

#[test]
fn honest_ballots_verify_at_every_level() {
    let (mut rng, h) = setup();
    for yes in 1..=L {
        let (b, _) = Ballot::build(AUCTION, &h, L, yes, &mut rng).unwrap();
        assert_eq!(b.verify(&AUCTION, &h, L), Ok(()), "yes_levels={yes}");
    }
}

#[test]
fn build_rejects_out_of_range_levels() {
    let (mut rng, h) = setup();
    assert!(Ballot::build(AUCTION, &h, L, 0, &mut rng).is_err());
    assert!(Ballot::build(AUCTION, &h, L, L + 1, &mut rng).is_err());
}

#[test]
fn rejects_cell_encrypting_two() {
    let (mut rng, h) = setup();
    let mut v = values(5);
    v[0] = 2;
    let (b, _) = Ballot::build_from_values(AUCTION, &h, &v, &mut rng);
    assert_eq!(b.verify(&AUCTION, &h, L), Err(Error::BadBallot("bit proof")));
}

#[test]
fn rejects_non_monotone_vector() {
    let (mut rng, h) = setup();
    let mut v = values(3);
    v[6] = 1; // 1 1 1 0 0 0 1 0 ...
    let (b, _) = Ballot::build_from_values(AUCTION, &h, &v, &mut rng);
    assert_eq!(b.verify(&AUCTION, &h, L), Err(Error::BadBallot("monotone proof")));
}

#[test]
fn rejects_all_zero_vector() {
    let (mut rng, h) = setup();
    let (b, _) = Ballot::build_from_values(AUCTION, &h, &values(0), &mut rng);
    assert_eq!(b.verify(&AUCTION, &h, L), Err(Error::BadBallot("first-one proof")));
}

#[test]
fn rejects_wrong_auction_id() {
    let (mut rng, h) = setup();
    let (mut b, _) = Ballot::build(AUCTION, &h, L, 4, &mut rng).unwrap();
    let other = [8u8; 32];
    assert_eq!(b.verify(&other, &h, L), Err(Error::BadBallot("auction_id")));
    // Relabelling the ballot breaks the signature, and re-signing with a
    // fresh key still fails because every proof transcript binds auction_id.
    b.auction_id = other;
    assert_eq!(b.verify(&other, &h, L), Err(Error::BadBallot("signature")));
}

#[test]
fn rejects_bad_signature_and_swapped_key() {
    let (mut rng, h) = setup();
    let (b, _) = Ballot::build(AUCTION, &h, L, 4, &mut rng).unwrap();

    let mut tampered = b.clone();
    tampered.sig.s += tally_crypto::Scalar::from(1u64);
    assert_eq!(tampered.verify(&AUCTION, &h, L), Err(Error::BadBallot("signature")));

    // Steal someone's ciphertexts under a new ballot key: re-signing works,
    // but the proofs are bound to the original P.
    let thief = random_scalar(&mut rng);
    let mut stolen = b.clone();
    stolen.p = g() * thief;
    stolen.sig = tally_crypto::schnorr::sign(tally_crypto::ballot::SIG_PURPOSE, &thief, &stolen.body_hash(), &mut rng);
    assert_eq!(stolen.verify(&AUCTION, &h, L), Err(Error::BadBallot("bit proof")));
}

#[test]
fn rejects_tampered_ciphertext_and_wrong_shape() {
    let (mut rng, h) = setup();
    let (b, _) = Ballot::build(AUCTION, &h, L, 4, &mut rng).unwrap();

    let mut t = b.clone();
    t.c[3] = t.c[3] + Ciphertext::encrypt(&h, 1, &random_scalar(&mut rng));
    assert!(t.verify(&AUCTION, &h, L).is_err());

    assert_eq!(b.verify(&AUCTION, &h, L - 1), Err(Error::BadBallot("shape")));
}

#[test]
fn json_roundtrip_and_size() {
    let (mut rng, h) = setup();
    let (b, _) = Ballot::build(AUCTION, &h, L, 9, &mut rng).unwrap();
    let json = serde_json::to_string(&b).unwrap();
    let back: Ballot = serde_json::from_str(&json).unwrap();
    assert_eq!(back, b);
    assert_eq!(back.verify(&AUCTION, &h, L), Ok(()));
    // Spec estimated 5–6 KB; hex JSON is larger. Keep it under 12 KB.
    assert!(json.len() < 12_000, "ballot json is {} bytes", json.len());
    println!("ballot json size: {} bytes", json.len());
}

#[test]
fn json_rejects_off_curve_point() {
    let (mut rng, h) = setup();
    let (b, _) = Ballot::build(AUCTION, &h, L, 2, &mut rng).unwrap();
    let json = serde_json::to_string(&b).unwrap();
    let p_hex = tally_crypto::codec::point_to_hex(&b.p);
    let bad = json.replacen(&p_hex, &"ff".repeat(32), 1);
    assert!(serde_json::from_str::<Ballot>(&bad).is_err());
}
