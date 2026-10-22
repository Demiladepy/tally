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
//! * The bonded set is accepted only after close, with ≥ t committee
//!   member signatures over the final root.
//! * A decryption record is accepted only after the bonded set, only if its
//!   ciphertext is the recomputed tally T_k or bonded ballot cell it names,
//!   only if at least t shares verify, and only if clearing still needs that
//!   target (`next_targets`), so nothing beyond the binary search is opened.
//! * A result is accepted only if it recomputes exactly from the log.
//! * A settlement is accepted only if the seller signed it for a winner.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderValue};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use tally_crypto::auction::{AuctionLog, AuctionResult, BondAttestation, Entry, Settlement};
use tally_crypto::ballot::Ballot;
use tally_crypto::codec;
use tally_crypto::manifest::{Close, Manifest, Receipt};
use tally_crypto::threshold::{self, DecryptionRecord};
use tally_crypto::{g, log, Point, Scalar};
use tokio::sync::Mutex;
use tower_http::set_header::SetResponseHeaderLayer;

/// Self-only: no third-party scripts, styles, fonts or connections. WASM is
/// allowed to compile; nothing may frame the app.
const CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// A ballot at L = 16 is ~12 KB of JSON; nothing legitimate is bigger.
const BODY_LIMIT: usize = 64 * 1024;

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
        self.router_with_web(None)
    }

    /// Also serve the static web app (verify page, bidding UI) from `web`,
    /// same origin as the API, under a strict self-only CSP.
    pub fn router_with_web(self, web: Option<PathBuf>) -> Router {
        let api = Router::new()
            .route("/v1/info", get(info))
            .route("/v1/auctions", post(create).get(list))
            .route("/v1/auctions/{id}", get(get_log))
            .route("/v1/auctions/{id}/ballots", post(append))
            .route("/v1/auctions/{id}/close", post(close))
            .route("/v1/auctions/{id}/bonds", post(add_bonds))
            .route("/v1/auctions/{id}/decryptions", post(add_decryption))
            .route("/v1/auctions/{id}/result", post(add_result))
            .route("/v1/auctions/{id}/settlements", post(add_settlement))
            .layer(DefaultBodyLimit::max(BODY_LIMIT))
            .with_state(Arc::new(self));
        let app = match web {
            Some(dir) => api.fallback_service(tower_http::services::ServeDir::new(dir)),
            None => api,
        };
        app.layer(SetResponseHeaderLayer::overriding(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP)))
            .layer(SetResponseHeaderLayer::overriding(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")))
            .layer(SetResponseHeaderLayer::overriding(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
            .layer(SetResponseHeaderLayer::overriding(
                header::HeaderName::from_static("permissions-policy"),
                HeaderValue::from_static("camera=(), microphone=(), geolocation=(), interest-cohort=()"),
            ))
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
    let log = AuctionLog {
        manifest: m.clone(),
        bulletin_pk: b.pk,
        entries: vec![],
        close: None,
        bonds: None,
        decryptions: vec![],
        result: None,
        settlements: vec![],
    };
    b.persist(&log)?;
    all.insert(m.auction_id, Auction { log: log.clone(), seen_p: HashSet::new() });
    Ok(Json(log))
}

#[derive(Serialize)]
struct AuctionSummary {
    auction_id: String,
    supply: u64,
    levels: usize,
    ballots: usize,
    closed: bool,
    cleared: bool,
}

async fn list(State(b): State<Shared>) -> Json<Vec<AuctionSummary>> {
    let all = b.auctions.lock().await;
    let mut out: Vec<AuctionSummary> = all
        .values()
        .map(|a| AuctionSummary {
            auction_id: hex::encode(a.log.manifest.auction_id),
            supply: a.log.manifest.supply,
            levels: a.log.manifest.levels(),
            ballots: a.log.entries.len(),
            closed: a.log.close.is_some(),
            cleared: a.log.result.is_some(),
        })
        .collect();
    out.sort_by(|x, y| x.auction_id.cmp(&y.auction_id));
    Json(out)
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

/// Run `f` on the auction, persist, and roll back if storage fails.
async fn mutate<T>(
    b: &Bulletin,
    id: &str,
    f: impl FnOnce(&mut AuctionLog) -> Result<T, (StatusCode, &'static str)>,
) -> ApiResult<T> {
    let id = auction_id(id)?;
    let mut all = b.auctions.lock().await;
    let a = all.get_mut(&id).ok_or_else(not_found)?;
    let before = a.log.clone();
    let out = f(&mut a.log)?;
    if let Err(e) = b.persist(&a.log) {
        a.log = before;
        return Err(e);
    }
    Ok(Json(out))
}

async fn add_bonds(State(b): State<Shared>, Path(id): Path<String>, Json(att): Json<BondAttestation>) -> ApiResult<usize> {
    mutate(&b, &id, |log| {
        if log.close.is_none() {
            return Err((StatusCode::CONFLICT, "auction still open"));
        }
        if log.bonds.is_some() {
            return Err((StatusCode::CONFLICT, "bonded set already attested"));
        }
        let in_range = att.bonded.iter().all(|i| (*i as usize) < log.entries.len());
        if att.auction_id != log.manifest.auction_id || att.root != log.head() || !in_range || !att.verify(&log.manifest.committee.key) {
            return Err(bad("attestation rejected"));
        }
        let n = att.bonded.len();
        log.bonds = Some(att);
        Ok(n)
    })
    .await
}

async fn add_decryption(
    State(b): State<Shared>,
    Path(id): Path<String>,
    Json(rec): Json<DecryptionRecord>,
) -> ApiResult<usize> {
    mutate(&b, &id, |log| {
        if log.bonds.is_none() {
            return Err((StatusCode::CONFLICT, "bonded set not attested yet"));
        }
        let wanted = log.next_targets().map_err(|_| bad("clearing state"))?;
        if !wanted.contains(&rec.target) {
            return Err((StatusCode::CONFLICT, "target not needed by clearing"));
        }
        let ct = log.target_ciphertext(&rec.target).ok_or_else(|| bad("unknown target"))?;
        if ct != rec.ciphertext() || !threshold::verify_record(&log.manifest.committee.key, &rec) {
            return Err(bad("decryption rejected"));
        }
        log.decryptions.push(rec);
        Ok(log.decryptions.len())
    })
    .await
}

async fn add_result(State(b): State<Shared>, Path(id): Path<String>, Json(r): Json<AuctionResult>) -> ApiResult<usize> {
    mutate(&b, &id, |log| {
        if log.result.is_some() {
            return Err((StatusCode::CONFLICT, "result already published"));
        }
        if log.compute_result(r.close_block_hash).as_ref() != Ok(&r) {
            return Err(bad("result does not recompute from the log"));
        }
        let n = r.winners.len();
        log.result = Some(r);
        Ok(n)
    })
    .await
}

async fn add_settlement(State(b): State<Shared>, Path(id): Path<String>, Json(s): Json<Settlement>) -> ApiResult<usize> {
    mutate(&b, &id, |log| {
        let Some(r) = &log.result else { return Err((StatusCode::CONFLICT, "no result yet")) };
        if !r.winners.contains(&s.p) || !s.verify(&log.manifest.auction_id, &log.manifest.seller_pk) {
            return Err(bad("settlement rejected"));
        }
        if log.settlements.iter().any(|x| x.p == s.p) {
            return Err((StatusCode::CONFLICT, "winner already settled"));
        }
        log.settlements.push(s);
        Ok(log.settlements.len())
    })
    .await
}
