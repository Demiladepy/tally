//! Bulletin API: honest flow, every rejection path, and reload from disk.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::Value;
use tally_bulletin::{AuctionLog, Bulletin};
use tally_crypto::ballot::Ballot;
use tally_crypto::manifest::{Close, Committee, Manifest, Receipt};
use tally_crypto::schnorr::Signature;
use tally_crypto::threshold;
use tally_crypto::{clearing, dkg, g, random_scalar, Point, Scalar};
use tower::ServiceExt;

const L: usize = 16;

struct Fixture {
    rng: ChaCha20Rng,
    manifest: Manifest,
    seller_sk: Scalar,
    member_sks: Vec<Scalar>,
    bulletin_pk: Point,
    id: String,
}

fn fixture(seed: u64) -> (Fixture, Bulletin) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let dealings: Vec<_> = (1..=3).map(|i| dkg::deal(i, 3, 2, &mut rng).unwrap()).collect();
    let key = dkg::committee_key(3, 2, &dealings.iter().map(|d| d.commitments.clone()).collect::<Vec<_>>()).unwrap();
    let member_sks = (1..=3u32)
        .map(|j| {
            let rec: Vec<_> = dealings.iter().map(|d| (d.dealer, d.commitments.as_slice(), d.shares[j as usize - 1])).collect();
            dkg::member_secret(j, &rec).unwrap()
        })
        .collect();
    let seller_sk = random_scalar(&mut rng);
    let mut manifest = Manifest {
        v: 1,
        auction_id: [seed as u8; 32],
        collection_id: [2; 32],
        supply: 2,
        ladder_zat: (0..L as u64).map(|i| 50_000_000 + i * 10_000_000).collect(),
        bond_zat: 1_000_000,
        open_height: 100,
        close_height: 200,
        settle_window_blocks: 100,
        min_batch: 3,
        committee: Committee { key, members: vec!["a".into(), "b".into(), "c".into()] },
        escrow_ua: "utest1escrow".into(),
        forfeit_ua: "utest1forfeit".into(),
        seller_pk: g() * seller_sk,
        sig: Signature { r: g(), s: Scalar::from(0u64) },
    };
    manifest.sign(&seller_sk, &mut rng);
    let bsk = random_scalar(&mut rng);
    let id = hex::encode(manifest.auction_id);
    let f = Fixture { rng, manifest, seller_sk, member_sks, bulletin_pk: g() * bsk, id };
    (f, Bulletin::new(bsk, None).unwrap())
}

async fn call(app: &Router, method: &str, uri: &str, body: Option<String>) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(body.map(Body::from).unwrap_or_else(Body::empty))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn ballot(f: &mut Fixture, yes: usize) -> Ballot {
    Ballot::build(f.manifest.auction_id, &f.manifest.committee.key.h, L, yes, &mut f.rng).unwrap().0
}

#[tokio::test]
async fn full_flow_and_rejections() {
    let (mut f, b) = fixture(1);
    let app = b.router();
    let m = serde_json::to_string(&f.manifest).unwrap();
    assert_eq!(call(&app, "POST", "/v1/auctions", Some(m.clone())).await.0, StatusCode::OK);
    // Idempotent for the same manifest; a different one under the same id is refused.
    assert_eq!(call(&app, "POST", "/v1/auctions", Some(m)).await.0, StatusCode::OK);
    let mut other = f.manifest.clone();
    other.supply = 3;
    other.sign(&f.seller_sk, &mut f.rng);
    assert_eq!(call(&app, "POST", "/v1/auctions", Some(serde_json::to_string(&other).unwrap())).await.0, StatusCode::CONFLICT);

    let url = format!("/v1/auctions/{}/ballots", f.id);
    let mut ballots = vec![];
    for (i, yes) in [3usize, 9, 9, 12].into_iter().enumerate() {
        let bl = ballot(&mut f, yes);
        let (s, v) = call(&app, "POST", &url, Some(serde_json::to_string(&bl).unwrap())).await;
        assert_eq!(s, StatusCode::OK);
        let r: Receipt = serde_json::from_value(v).unwrap();
        assert_eq!(r.i, i as u64);
        assert!(r.verify(&f.bulletin_pk));
        ballots.push(bl);
    }

    // Same ballot key twice.
    let dup = serde_json::to_string(&ballots[0]).unwrap();
    assert_eq!(call(&app, "POST", &url, Some(dup)).await.0, StatusCode::CONFLICT);
    // Invalid proofs (non-monotone vector).
    let mut v = vec![1u64; 3];
    v.extend([0, 1]);
    v.resize(L, 0);
    let (forged, _) = Ballot::build_from_values(f.manifest.auction_id, &f.manifest.committee.key.h, &v, &mut f.rng);
    assert_eq!(call(&app, "POST", &url, Some(serde_json::to_string(&forged).unwrap())).await.0, StatusCode::BAD_REQUEST);
    // Ballot for another auction.
    let (alien, _) = Ballot::build([9; 32], &f.manifest.committee.key.h, L, 2, &mut f.rng).unwrap();
    assert_eq!(call(&app, "POST", &url, Some(serde_json::to_string(&alien).unwrap())).await.0, StatusCode::BAD_REQUEST);
    // Garbage and oversize bodies.
    assert!(call(&app, "POST", &url, Some("{\"v\":1}".into())).await.0.is_client_error());
    assert!(call(&app, "POST", &url, Some("x".repeat(70_000))).await.0.is_client_error());

    // Decryption before close is refused.
    let dec_url = format!("/v1/auctions/{}/decryptions", f.id);
    let totals = clearing::tally(&ballots, L);
    let rec = decrypt(&mut f, "T_9", &totals[8], 4);
    assert_eq!(call(&app, "POST", &dec_url, Some(serde_json::to_string(&rec).unwrap())).await.0, StatusCode::CONFLICT);

    // Close: wrong root refused, wrong signer refused, correct one accepted.
    let (_, logv) = call(&app, "GET", &format!("/v1/auctions/{}", f.id), None).await;
    let log: AuctionLog = serde_json::from_value(logv).unwrap();
    let root = log.head();
    assert_eq!(root, tally_crypto::log::root(&f.manifest.auction_id, ballots.iter().map(|b| b.body_hash()).collect::<Vec<_>>().iter()));
    let close_url = format!("/v1/auctions/{}/close", f.id);
    let bad_root = Close::sign(&f.seller_sk, f.manifest.auction_id, 4, [0; 32], &mut f.rng);
    assert_eq!(call(&app, "POST", &close_url, Some(serde_json::to_string(&bad_root).unwrap())).await.0, StatusCode::CONFLICT);
    let impostor = random_scalar(&mut f.rng);
    let bad_sig = Close::sign(&impostor, f.manifest.auction_id, 4, root, &mut f.rng);
    assert_eq!(call(&app, "POST", &close_url, Some(serde_json::to_string(&bad_sig).unwrap())).await.0, StatusCode::BAD_REQUEST);
    let ok = Close::sign(&f.seller_sk, f.manifest.auction_id, 4, root, &mut f.rng);
    assert_eq!(call(&app, "POST", &close_url, Some(serde_json::to_string(&ok).unwrap())).await.0, StatusCode::OK);

    // No ballots after close.
    let late = ballot(&mut f, 5);
    assert_eq!(call(&app, "POST", &url, Some(serde_json::to_string(&late).unwrap())).await.0, StatusCode::CONFLICT);

    // Decryptions: the right T_k is accepted once; a record whose ciphertext
    // isn't the named target, a forged m, or a repeat is refused.
    assert_eq!(rec.m, 3);
    assert_eq!(call(&app, "POST", &dec_url, Some(serde_json::to_string(&rec).unwrap())).await.0, StatusCode::OK);
    assert_eq!(call(&app, "POST", &dec_url, Some(serde_json::to_string(&rec).unwrap())).await.0, StatusCode::CONFLICT);
    let wrong = decrypt(&mut f, "T_2", &totals[8], 4);
    assert_eq!(call(&app, "POST", &dec_url, Some(serde_json::to_string(&wrong).unwrap())).await.0, StatusCode::BAD_REQUEST);
    let mut lie = decrypt(&mut f, "T_3", &totals[2], 4);
    lie.m += 1;
    assert_eq!(call(&app, "POST", &dec_url, Some(serde_json::to_string(&lie).unwrap())).await.0, StatusCode::BAD_REQUEST);
    let p_hex = tally_crypto::codec::point_to_hex(&ballots[1].p);
    let cell = decrypt(&mut f, &format!("ballot:{p_hex}:9"), &ballots[1].c[8], 1);
    assert_eq!(cell.m, 1);
    assert_eq!(call(&app, "POST", &dec_url, Some(serde_json::to_string(&cell).unwrap())).await.0, StatusCode::OK);
}

fn decrypt(f: &mut Fixture, target: &str, ct: &tally_crypto::elgamal::Ciphertext, max: u64) -> threshold::DecryptionRecord {
    let shares = [1u32, 3]
        .iter()
        .map(|&j| threshold::make_share(target, j, &f.member_sks[j as usize - 1], ct, &mut f.rng))
        .collect();
    threshold::decrypt(target, &f.manifest.committee.key, ct, shares, max).unwrap()
}

#[tokio::test]
async fn persists_and_reloads() {
    let dir = std::env::temp_dir().join(format!("tally-bulletin-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (mut f, _) = fixture(2);
    let bsk = random_scalar(&mut f.rng);
    let app = Bulletin::new(bsk, Some(dir.clone())).unwrap().router();
    call(&app, "POST", "/v1/auctions", Some(serde_json::to_string(&f.manifest).unwrap())).await;
    let bl = ballot(&mut f, 4);
    let url = format!("/v1/auctions/{}/ballots", f.id);
    assert_eq!(call(&app, "POST", &url, Some(serde_json::to_string(&bl).unwrap())).await.0, StatusCode::OK);

    // A restarted bulletin keeps the log and still refuses the duplicate.
    let app2 = Bulletin::new(bsk, Some(dir.clone())).unwrap().router();
    let (s, v) = call(&app2, "GET", &format!("/v1/auctions/{}", f.id), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["entries"].as_array().unwrap().len(), 1);
    assert_eq!(call(&app2, "POST", &url, Some(serde_json::to_string(&bl).unwrap())).await.0, StatusCode::CONFLICT);
    let _ = std::fs::remove_dir_all(&dir);
}
