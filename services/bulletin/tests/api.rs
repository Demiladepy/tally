//! Bulletin API: a whole auction through HTTP, every rejection path, the
//! public verifier going green, and reload from disk.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use serde_json::Value;
use tally_bulletin::{Bulletin, Limits};
use tally_crypto::auction::{self, AuctionLog, AuctionResult, BondAttestation, Outcome, Settlement};
use tally_crypto::ballot::Ballot;
use tally_crypto::manifest::{Close, Committee, Manifest, Receipt, MANIFEST_V2};
use tally_crypto::schnorr::Signature;
use tally_crypto::threshold;
use tally_crypto::{dkg, g, random_scalar, Point, Scalar};
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

fn fixture(seed: u64, supply: u64, min_batch: u64) -> (Fixture, Bulletin) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let dealings: Vec<_> = (1..=3).map(|i| dkg::deal(i, 3, 2, &mut rng).unwrap()).collect();
    let key = dkg::committee_key(3, 2, &dealings.iter().map(|d| d.commitments.clone()).collect::<Vec<_>>()).unwrap();
    let member_sks: Vec<Scalar> = (1..=3u32)
        .map(|j| {
            let rec: Vec<_> = dealings.iter().map(|d| (d.dealer, d.commitments.as_slice(), d.shares[j as usize - 1])).collect();
            dkg::member_secret(j, &rec).unwrap()
        })
        .collect();
    let seller_sk = random_scalar(&mut rng);
    let mut manifest = Manifest {
        v: MANIFEST_V2,
        auction_id: [0; 32],
        collection_id: [2; 32],
        supply,
        ladder_zat: (1..=L as u64).map(|i| i * 100_000).collect(),
        bond_zat: 100_000,
        open_height: 100,
        close_height: 200,
        settle_window_blocks: 100,
        min_batch,
        committee: Committee { key, members: vec!["a".into(), "b".into(), "c".into()] },
        escrow_ua: "utest1escrow".into(),
        forfeit_ua: "utest1forfeit".into(),
        seller_pk: g() * seller_sk,
        sig: Signature { r: g(), s: Scalar::from(0u64) },
        endorsements: vec![],
    };
    reseal(&mut manifest, &seller_sk, &member_sks, &mut rng);
    let bsk = random_scalar(&mut rng);
    let id = hex::encode(manifest.auction_id);
    let f = Fixture { rng, manifest, seller_sk, member_sks, bulletin_pk: g() * bsk, id };
    (f, Bulletin::new(bsk, None).unwrap())
}

/// Bind the id to the contents, sign as seller, endorse as every member.
fn reseal(m: &mut Manifest, seller_sk: &Scalar, member_sks: &[Scalar], rng: &mut ChaCha20Rng) {
    m.endorsements.clear();
    m.bind_id();
    m.sign(seller_sk, rng);
    m.endorsements = (1..=member_sks.len() as u32).map(|j| m.endorse(j, &member_sks[j as usize - 1], rng)).collect();
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

async fn post<T: Serialize>(app: &Router, uri: &str, v: &T) -> StatusCode {
    call(app, "POST", uri, Some(serde_json::to_string(v).unwrap())).await.0
}

async fn get_log(app: &Router, id: &str) -> AuctionLog {
    serde_json::from_value(call(app, "GET", &format!("/v1/auctions/{id}"), None).await.1).unwrap()
}

fn ballot(f: &mut Fixture, yes: usize) -> Ballot {
    Ballot::build(f.manifest.auction_id, &f.manifest.committee.key.h, L, yes, &mut f.rng).unwrap().0
}

fn attest(f: &mut Fixture, root: [u8; 32], bonded: &[u64], members: &[u32]) -> BondAttestation {
    let sigs = members
        .iter()
        .map(|&j| BondAttestation::sign_member(&f.manifest.auction_id, &root, bonded, j, &f.member_sks[j as usize - 1], &mut f.rng))
        .collect();
    BondAttestation { auction_id: f.manifest.auction_id, root, bonded: bonded.to_vec(), sigs }
}

fn decrypt(f: &mut Fixture, log: &AuctionLog, target: &str) -> threshold::DecryptionRecord {
    let ct = log.target_ciphertext(target).unwrap();
    let shares = [1u32, 3]
        .iter()
        .map(|&j| threshold::make_share(target, j, &f.member_sks[j as usize - 1], &ct, &mut f.rng))
        .collect();
    threshold::decrypt(target, &f.manifest.committee.key, &ct, shares, log.entries.len() as u64).unwrap()
}

/// Drive clearing exactly as the committee coordinator does.
async fn clear(f: &mut Fixture, app: &Router) -> AuctionLog {
    let dec_url = format!("/v1/auctions/{}/decryptions", f.id);
    loop {
        let log = get_log(app, &f.id).await;
        let next = log.next_targets().unwrap();
        if next.is_empty() {
            return log;
        }
        for t in next {
            let rec = decrypt(f, &log, &t);
            assert_eq!(post(app, &dec_url, &rec).await, StatusCode::OK, "{t}");
        }
    }
}

#[tokio::test]
async fn whole_auction_and_rejections() {
    let (mut f, b) = fixture(1, 2, 5);
    let app = b.router();
    assert_eq!(post(&app, "/v1/auctions", &f.manifest).await, StatusCode::OK);
    assert_eq!(post(&app, "/v1/auctions", &f.manifest).await, StatusCode::OK, "idempotent");
    // v2: a different manifest can't reuse the id (the id is its hash) ...
    let mut other = f.manifest.clone();
    other.supply = 3;
    other.sign(&f.seller_sk, &mut f.rng);
    assert_eq!(post(&app, "/v1/auctions", &other).await, StatusCode::BAD_REQUEST);
    // ... a member that never endorsed is refused ...
    let mut unendorsed = f.manifest.clone();
    unendorsed.endorsements.pop();
    assert_eq!(post(&app, "/v1/auctions", &unendorsed).await, StatusCode::BAD_REQUEST);
    // ... and legacy v1 can't open new auctions.
    let mut legacy = f.manifest.clone();
    legacy.v = 1;
    legacy.endorsements.clear();
    legacy.sign(&f.seller_sk, &mut f.rng);
    assert_eq!(post(&app, "/v1/auctions", &legacy).await, StatusCode::BAD_REQUEST);

    // Six bidders; entry 5 never pays a bond and must not count.
    let url = format!("/v1/auctions/{}/ballots", f.id);
    let mut ballots = vec![];
    for (i, yes) in [3usize, 9, 9, 12, 5, 16].into_iter().enumerate() {
        let bl = ballot(&mut f, yes);
        let (s, v) = call(&app, "POST", &url, Some(serde_json::to_string(&bl).unwrap())).await;
        assert_eq!(s, StatusCode::OK);
        let r: Receipt = serde_json::from_value(v).unwrap();
        assert_eq!(r.i, i as u64);
        assert!(r.verify(&f.bulletin_pk));
        ballots.push(bl);
    }

    assert_eq!(post(&app, &url, &ballots[0]).await, StatusCode::CONFLICT, "same ballot key twice");
    let mut v = vec![1u64; 3];
    v.extend([0, 1]);
    v.resize(L, 0);
    let (forged, _) = Ballot::build_from_values(f.manifest.auction_id, &f.manifest.committee.key.h, &v, &mut f.rng);
    assert_eq!(post(&app, &url, &forged).await, StatusCode::BAD_REQUEST, "non-monotone");
    let (alien, _) = Ballot::build([9; 32], &f.manifest.committee.key.h, L, 2, &mut f.rng).unwrap();
    assert_eq!(post(&app, &url, &alien).await, StatusCode::BAD_REQUEST, "other auction");
    assert!(call(&app, "POST", &url, Some("{\"v\":1}".into())).await.0.is_client_error());
    assert!(call(&app, "POST", &url, Some("x".repeat(70_000))).await.0.is_client_error());

    // Close: wrong root, wrong signer, then the real one.
    let root = get_log(&app, &f.id).await.head();
    let close_url = format!("/v1/auctions/{}/close", f.id);
    assert_eq!(post(&app, &close_url, &Close::sign(&f.seller_sk, f.manifest.auction_id, 6, [0; 32], &mut f.rng)).await, StatusCode::CONFLICT);
    let impostor = random_scalar(&mut f.rng);
    assert_eq!(post(&app, &close_url, &Close::sign(&impostor, f.manifest.auction_id, 6, root, &mut f.rng)).await, StatusCode::BAD_REQUEST);
    assert_eq!(post(&app, &close_url, &Close::sign(&f.seller_sk, f.manifest.auction_id, 6, root, &mut f.rng)).await, StatusCode::OK);
    assert_eq!(post(&app, &url, &ballot(&mut f, 5)).await, StatusCode::CONFLICT, "no ballots after close");

    // Nothing can be decrypted before the bonded set is attested.
    let dec_url = format!("/v1/auctions/{}/decryptions", f.id);
    let log = get_log(&app, &f.id).await;
    let mut early = log.clone();
    early.bonds = Some(attest(&mut f, root, &[0, 1, 2, 3, 5], &[1, 3]));
    let early_rec = decrypt(&mut f, &early, "T_9");
    assert_eq!(post(&app, &dec_url, &early_rec).await, StatusCode::CONFLICT);

    // Bond attestation: one signature is not a quorum; a wrong root is refused.
    let bonds_url = format!("/v1/auctions/{}/bonds", f.id);
    let bonded = [0u64, 1, 2, 3, 5];
    assert_eq!(post(&app, &bonds_url, &attest(&mut f, root, &bonded, &[2])).await, StatusCode::BAD_REQUEST);
    assert_eq!(post(&app, &bonds_url, &attest(&mut f, [1; 32], &bonded, &[1, 2])).await, StatusCode::BAD_REQUEST);
    assert_eq!(post(&app, &bonds_url, &attest(&mut f, root, &bonded, &[1, 2])).await, StatusCode::OK);

    // A target the binary search doesn't need yet is refused.
    let log = get_log(&app, &f.id).await;
    let want = log.next_targets().unwrap();
    // T_1 is the public bonded count (5 >= supply), so the search starts at 1.
    assert_eq!(want, vec!["T_9".to_string()], "first probe of the search over 16 levels");
    let premature = decrypt(&mut f, &log, "T_2");
    assert_eq!(post(&app, &dec_url, &premature).await, StatusCode::CONFLICT);
    let mut lie = decrypt(&mut f, &log, "T_9");
    lie.m += 1;
    assert_eq!(post(&app, &dec_url, &lie).await, StatusCode::BAD_REQUEST);

    let log = clear(&mut f, &app).await;
    // Bonded maxes are 3, 9, 9, 12, 16 with supply 2: T_12 = 2, T_13 = 1.
    let r = log.compute_result([5; 32]).unwrap();
    assert_eq!(r.outcome, Outcome::Cleared);
    assert_eq!(r.k_star, 12);
    assert_eq!(r.price_zat, Some(1_200_000));
    assert_eq!(r.winners.len(), 2);
    assert!(r.winners.contains(&ballots[3].p) && r.winners.contains(&ballots[5].p));
    assert!(!r.winners.contains(&ballots[4].p), "unbonded ballot never counts");
    assert!(r.totals.len() <= 5, "decrypted {} totals", r.totals.len());

    let result_url = format!("/v1/auctions/{}/result", f.id);
    let mut fake = r.clone();
    fake.price_zat = Some(100_000);
    assert_eq!(post(&app, &result_url, &fake).await, StatusCode::BAD_REQUEST);
    assert_eq!(post(&app, &result_url, &r).await, StatusCode::OK);

    // Before anyone settles, both winners are unsettled (and would forfeit
    // after the window); each settlement removes one.
    let log = get_log(&app, &f.id).await;
    assert_eq!(log.unsettled_winners().len(), 2);
    assert_eq!(log.forfeit_height(), 300);
    let settle_url = format!("/v1/auctions/{}/settlements", f.id);
    let loser = Settlement::sign(&f.seller_sk, &f.manifest.auction_id, ballots[0].p, "aa".into(), &mut f.rng);
    assert_eq!(post(&app, &settle_url, &loser).await, StatusCode::BAD_REQUEST);
    let forged = Settlement::sign(&impostor, &f.manifest.auction_id, r.winners[0], "bb".into(), &mut f.rng);
    assert_eq!(post(&app, &settle_url, &forged).await, StatusCode::BAD_REQUEST);
    for (i, w) in r.winners.iter().enumerate() {
        let s = Settlement::sign(&f.seller_sk, &f.manifest.auction_id, *w, format!("{i:064x}"), &mut f.rng);
        assert_eq!(post(&app, &settle_url, &s).await, StatusCode::OK);
    }

    let log = get_log(&app, &f.id).await;
    assert!(log.unsettled_winners().is_empty(), "both settled: nobody forfeits");
    let mut one_settled = log.clone();
    one_settled.settlements.pop();
    assert_eq!(one_settled.unsettled_winners(), vec![one_settled.result.as_ref().unwrap().winners[1]]);
    let checks = auction::verify(&log);
    for c in &checks {
        assert!(c.ok, "{}: {}", c.name, c.detail);
    }
    assert_eq!(checks.len(), 10);

    // Tampering with the served record turns the page red.
    let mut t = log.clone();
    t.result.as_mut().unwrap().winners.swap(0, 1);
    t.result.as_mut().unwrap().price_zat = Some(1_100_000);
    assert!(auction::verify(&t).iter().any(|c| !c.ok));
    let mut t = log.clone();
    t.entries[2].ballot.c[0] = t.entries[1].ballot.c[0];
    assert!(auction::verify(&t).iter().any(|c| !c.ok));
}

#[tokio::test]
async fn undersubscribed_and_void() {
    // Undersubscribed: 5 bonded ballots, supply 7: everyone wins at p_1, and
    // since T_1 is the public bonded count nothing at all is decrypted.
    let (mut f, b) = fixture(3, 7, 5);
    let app = b.router();
    post(&app, "/v1/auctions", &f.manifest).await;
    for yes in [2, 7, 16, 4, 11] {
        let bl = ballot(&mut f, yes);
        post(&app, &format!("/v1/auctions/{}/ballots", f.id), &bl).await;
    }
    let root = get_log(&app, &f.id).await.head();
    post(&app, &format!("/v1/auctions/{}/close", f.id), &Close::sign(&f.seller_sk, f.manifest.auction_id, 5, root, &mut f.rng)).await;
    post(&app, &format!("/v1/auctions/{}/bonds", f.id), &attest(&mut f, root, &[0, 1, 2, 3, 4], &[1, 3])).await;
    let log = clear(&mut f, &app).await;
    let r: AuctionResult = log.compute_result([0; 32]).unwrap();
    assert_eq!(r.outcome, Outcome::Undersubscribed);
    assert_eq!(r.price_zat, Some(100_000));
    assert_eq!(r.winners.len(), 5);
    assert!(log.decryptions.is_empty(), "nothing decrypted: {:?}", log.decryptions.iter().map(|d| &d.target).collect::<Vec<_>>());

    // Void: 2 bonded < min_batch 5, so nothing at all is decrypted.
    let (mut f, b) = fixture(4, 1, 5);
    let app = b.router();
    post(&app, "/v1/auctions", &f.manifest).await;
    for yes in [4, 9] {
        let bl = ballot(&mut f, yes);
        post(&app, &format!("/v1/auctions/{}/ballots", f.id), &bl).await;
    }
    let root = get_log(&app, &f.id).await.head();
    post(&app, &format!("/v1/auctions/{}/close", f.id), &Close::sign(&f.seller_sk, f.manifest.auction_id, 2, root, &mut f.rng)).await;
    post(&app, &format!("/v1/auctions/{}/bonds", f.id), &attest(&mut f, root, &[0, 1], &[2, 3])).await;
    let log = get_log(&app, &f.id).await;
    assert!(log.next_targets().unwrap().is_empty());
    let r = log.compute_result([0; 32]).unwrap();
    assert_eq!(r.outcome, Outcome::Void);
    assert_eq!(post(&app, &format!("/v1/auctions/{}/result", f.id), &r).await, StatusCode::OK);
    let log = get_log(&app, &f.id).await;
    assert!(auction::verify(&log).iter().all(|c| c.ok));
}

#[tokio::test]
async fn rejections_never_echo_input() {
    let (f, b) = fixture(6, 1, 5);
    let app = b.router();
    post(&app, "/v1/auctions", &f.manifest).await;
    let marker = "utest1leakcanaryleakcanary";
    for (uri, body) in [
        (format!("/v1/auctions/{}/ballots", f.id), format!("{{\"P\":\"{marker}\"}}")),
        (format!("/v1/auctions/{}/ballots", f.id), format!("[\"{marker}\"")),
        ("/v1/auctions".to_string(), format!("{{\"v\":2,\"escrow_ua\":{marker}}}")),
        (format!("/v1/auctions/{}/settlements", f.id), format!("{{\"txid\":\"{marker}\"}}")),
    ] {
        let req = Request::builder()
            .method("POST")
            .uri(&uri)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert!(resp.status().is_client_error(), "{uri}");
        let text = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(!text.contains("leakcanary"), "{uri} echoed input: {text}");
    }
}

#[tokio::test]
async fn limits_stop_spam() {
    let (mut f, b) = fixture(5, 1, 5);
    let app = b.with_limits(Limits { max_auctions: 1, max_ballots_per_auction: 2 }).router();
    assert_eq!(post(&app, "/v1/auctions", &f.manifest).await, StatusCode::OK);
    let url = format!("/v1/auctions/{}/ballots", f.id);
    for _ in 0..2 {
        let bl = ballot(&mut f, 3);
        assert_eq!(post(&app, &url, &bl).await, StatusCode::OK);
    }
    let bl = ballot(&mut f, 3);
    assert_eq!(post(&app, &url, &bl).await, StatusCode::INSUFFICIENT_STORAGE);
    let mut other = f.manifest.clone();
    other.supply = 2;
    let members = f.member_sks.clone();
    reseal(&mut other, &f.seller_sk, &members, &mut f.rng);
    assert_ne!(other.auction_id, f.manifest.auction_id);
    assert_eq!(post(&app, "/v1/auctions", &other).await, StatusCode::INSUFFICIENT_STORAGE);
}

#[tokio::test]
async fn persists_and_reloads() {
    let dir = std::env::temp_dir().join(format!("tally-bulletin-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (mut f, _) = fixture(2, 2, 5);
    let bsk = random_scalar(&mut f.rng);
    let app = Bulletin::new(bsk, Some(dir.clone())).unwrap().router();
    post(&app, "/v1/auctions", &f.manifest).await;
    let bl = ballot(&mut f, 4);
    let url = format!("/v1/auctions/{}/ballots", f.id);
    assert_eq!(post(&app, &url, &bl).await, StatusCode::OK);

    // A restarted bulletin keeps the log and still refuses the duplicate.
    let app2 = Bulletin::new(bsk, Some(dir.clone())).unwrap().router();
    assert_eq!(get_log(&app2, &f.id).await.entries.len(), 1);
    assert_eq!(post(&app2, &url, &bl).await, StatusCode::CONFLICT);
    let _ = std::fs::remove_dir_all(&dir);
}
