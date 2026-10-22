//! Tally bulletin: an append-only, hash-chained log of encrypted ballots.
//!
//! Privacy rules (THREAT_MODEL.md):
//! * No request logging of any kind: no IPs, user agents or timings. There
//!   is no tracing layer, and errors never echo request contents.
//! * Only what is already public is stored: the signed manifest, ballots
//!   (ciphertexts and proofs, no addresses), the close record, and committee
//!   decryption records.
//!
//! Integrity rules:
//! * A ballot is appended only if every proof and its signature verify
//!   against the manifest, and its ballot key P has not been seen.
//! * Each append returns a receipt signed by the bulletin key. A bidder whose
//!   receipted entry is missing from the final log can prove censorship.
//! * Only the seller can close, and only at the exact (count, root).
//! * A decryption record is accepted only after close, only if its
//!   ciphertext is the recomputed tally T_k or ballot cell it names, and only
//!   if at least t shares verify.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tally_crypto::ballot::Ballot;
use tally_crypto::clearing;
use tally_crypto::codec;
use tally_crypto::manifest::{Close, Manifest, Receipt};
use tally_crypto::threshold::{self, DecryptionRecord};
use tally_crypto::{g, log, Point, Scalar};
use tokio::sync::Mutex;

/// A ballot at L = 16 is ~12 KB of JSON; nothing legitimate is bigger.
const BODY_LIMIT: usize = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub i: u64,
    pub ballot: Ballot,
    #[serde(with = "codec::bytes32")]
    pub prev_hash: [u8; 32],
    #[serde(with = "codec::bytes32")]
    pub entry_hash: [u8; 32],
}

/// The whole public record of one auction; also mirrored as a static file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuctionLog {
    pub manifest: Manifest,
    #[serde(with = "codec::point")]
    pub bulletin_pk: Point,
    pub entries: Vec<Entry>,
    pub close: Option<Close>,
    pub decryptions: Vec<DecryptionRecord>,
}

impl AuctionLog {
    pub fn head(&self) -> [u8; 32] {
        self.entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or_else(|| log::genesis(&self.manifest.auction_id))
    }
}

struct Auction {
    log: AuctionLog,
    seen_p: HashSet<[u8; 32]>,
}

pub struct Bulletin {
    sk: Scalar,
    pk: Point,
    dir: Option<PathBuf>,
    auctions: Mutex<HashMap<[u8; 32], Auction>>,
}

type Shared = Arc<Bulletin>;
type ApiResult<T> = Result<Json<T>, (StatusCode, &'static str)>;

fn bad(msg: &'static str) -> (StatusCode, &'static str) {
    (StatusCode::BAD_REQUEST, msg)
}

fn not_found() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "unknown auction")
}

fn auction_id(s: &str) -> Result<[u8; 32], (StatusCode, &'static str)> {
    codec::bytes32_from_hex(s).map_err(|_| bad("bad auction id"))
}

impl Bulletin {
    /// `dir` = None keeps everything in memory (tests).
    pub fn new(sk: Scalar, dir: Option<PathBuf>) -> anyhow::Result<Self> {
        let mut auctions = HashMap::new();
        if let Some(d) = &dir {
            std::fs::create_dir_all(d)?;
            for f in std::fs::read_dir(d)? {
                let path = f?.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let log: AuctionLog = serde_json::from_slice(&std::fs::read(&path)?)?;
                let seen_p = log.entries.iter().map(|e| codec_p(&e.ballot.p)).collect();
                auctions.insert(log.manifest.auction_id, Auction { log, seen_p });
            }
        }
        Ok(Self { sk, pk: g() * sk, dir, auctions: Mutex::new(auctions) })
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/v1/info", get(info))
            .route("/v1/auctions", post(create))
            .route("/v1/auctions/{id}", get(get_log))
            .route("/v1/auctions/{id}/ballots", post(append))
            .route("/v1/auctions/{id}/close", post(close))
            .route("/v1/auctions/{id}/decryptions", post(add_decryption))
            .layer(DefaultBodyLimit::max(BODY_LIMIT))
            .with_state(Arc::new(self))
    }

    /// Write the static mirror atomically (temp file + rename).
    fn persist(&self, log: &AuctionLog) -> Result<(), (StatusCode, &'static str)> {
        let Some(dir) = &self.dir else { return Ok(()) };
        let name = hex::encode(log.manifest.auction_id);
        let tmp = dir.join(format!("{name}.json.tmp"));
        let dst = dir.join(format!("{name}.json"));
        let bytes = serde_json::to_vec(log).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "encode"))?;
        std::fs::write(&tmp, bytes)
            .and_then(|_| std::fs::rename(&tmp, &dst))
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "storage"))
    }
}

fn codec_p(p: &Point) -> [u8; 32] {
    codec::point_to_bytes(p)
}

#[derive(Serialize)]
struct Info {
    #[serde(with = "codec::point")]
    bulletin_pk: Point,
}

async fn info(State(b): State<Shared>) -> Json<Info> {
    Json(Info { bulletin_pk: b.pk })
}

async fn create(State(b): State<Shared>, Json(m): Json<Manifest>) -> ApiResult<AuctionLog> {
    m.verify().map_err(|_| bad("manifest rejected"))?;
    let mut all = b.auctions.lock().await;
    if let Some(a) = all.get(&m.auction_id) {
        // Idempotent for the identical manifest; never replaceable.
        return if a.log.manifest == m { Ok(Json(a.log.clone())) } else { Err((StatusCode::CONFLICT, "auction exists")) };
    }
    let log = AuctionLog { manifest: m.clone(), bulletin_pk: b.pk, entries: vec![], close: None, decryptions: vec![] };
    b.persist(&log)?;
    all.insert(m.auction_id, Auction { log: log.clone(), seen_p: HashSet::new() });
    Ok(Json(log))
}

async fn get_log(State(b): State<Shared>, Path(id): Path<String>) -> ApiResult<AuctionLog> {
    let id = auction_id(&id)?;
    let all = b.auctions.lock().await;
    all.get(&id).map(|a| Json(a.log.clone())).ok_or_else(not_found)
}

async fn append(State(b): State<Shared>, Path(id): Path<String>, Json(ballot): Json<Ballot>) -> ApiResult<Receipt> {
    let id = auction_id(&id)?;
    let mut all = b.auctions.lock().await;
    let a = all.get_mut(&id).ok_or_else(not_found)?;
    if a.log.close.is_some() {
        return Err((StatusCode::CONFLICT, "auction closed"));
    }
    let m = &a.log.manifest;
    ballot
        .verify(&m.auction_id, &m.committee.key.h, m.levels())
        .map_err(|_| bad("ballot rejected"))?;
    let p = codec_p(&ballot.p);
    if a.seen_p.contains(&p) {
        return Err((StatusCode::CONFLICT, "ballot key already used"));
    }

    let prev_hash = a.log.head();
    let entry_hash = log::entry_hash(&prev_hash, &ballot.body_hash());
    let i = a.log.entries.len() as u64;
    a.log.entries.push(Entry { i, ballot, prev_hash, entry_hash });
    if let Err(e) = b.persist(&a.log) {
        a.log.entries.pop();
        return Err(e);
    }
    a.seen_p.insert(p);
    Ok(Json(Receipt::issue(&b.sk, id, i, entry_hash, &mut rand_core::OsRng)))
}

async fn close(State(b): State<Shared>, Path(id): Path<String>, Json(c): Json<Close>) -> ApiResult<AuctionLog> {
    let id = auction_id(&id)?;
    let mut all = b.auctions.lock().await;
    let a = all.get_mut(&id).ok_or_else(not_found)?;
    if a.log.close.is_some() {
        return Err((StatusCode::CONFLICT, "already closed"));
    }
    if c.auction_id != id || !c.verify(&a.log.manifest.seller_pk) {
        return Err(bad("close rejected"));
    }
    if c.count != a.log.entries.len() as u64 || c.root != a.log.head() {
        return Err((StatusCode::CONFLICT, "log moved; re-read and sign the current head"));
    }
    a.log.close = Some(c);
    if let Err(e) = b.persist(&a.log) {
        a.log.close = None;
        return Err(e);
    }
    Ok(Json(a.log.clone()))
}

/// The ciphertext a decryption target names, recomputed from the log.
pub fn target_ciphertext(log: &AuctionLog, target: &str) -> Option<tally_crypto::elgamal::Ciphertext> {
    let levels = log.manifest.levels();
    if let Some(k) = target.strip_prefix("T_") {
        let k: usize = k.parse().ok()?;
        if k == 0 || k > levels {
            return None;
        }
        let ballots: Vec<Ballot> = log.entries.iter().map(|e| e.ballot.clone()).collect();
        return Some(clearing::tally(&ballots, levels)[k - 1]);
    }
    let rest = target.strip_prefix("ballot:")?;
    let (p_hex, k) = rest.rsplit_once(':')?;
    let k: usize = k.parse().ok()?;
    let e = log.entries.iter().find(|e| codec::point_to_hex(&e.ballot.p) == p_hex)?;
    if k == 0 || k > levels {
        return None;
    }
    Some(e.ballot.c[k - 1])
}

async fn add_decryption(
    State(b): State<Shared>,
    Path(id): Path<String>,
    Json(rec): Json<DecryptionRecord>,
) -> ApiResult<usize> {
    let id = auction_id(&id)?;
    let mut all = b.auctions.lock().await;
    let a = all.get_mut(&id).ok_or_else(not_found)?;
    if a.log.close.is_none() {
        return Err((StatusCode::CONFLICT, "auction still open"));
    }
    if a.log.decryptions.iter().any(|d| d.target == rec.target) {
        return Err((StatusCode::CONFLICT, "target already decrypted"));
    }
    let ct = target_ciphertext(&a.log, &rec.target).ok_or_else(|| bad("unknown target"))?;
    if ct != rec.ciphertext() || !threshold::verify_record(&a.log.manifest.committee.key, &rec) {
        return Err(bad("decryption rejected"));
    }
    a.log.decryptions.push(rec);
    if let Err(e) = b.persist(&a.log) {
        a.log.decryptions.pop();
        return Err(e);
    }
    Ok(Json(a.log.decryptions.len()))
}
