//! Browser bindings for Tally over a plain C ABI: JSON in, JSON out.
//!
//! JS calls `tally_alloc(len)`, copies UTF-8 JSON in, calls a function with
//! (ptr, len), then reads the reply at `tally_out_ptr()` / `tally_out_len()`.
//! Every reply is `{"ok": ...}` or `{"err": "..."}`. No wasm-bindgen, no
//! imports: the module needs nothing from the host.
//!
//! Randomness: the browser passes 32 bytes from `crypto.getRandomValues`,
//! which seed a ChaCha20 CSPRNG for one call.
//!
//! The bid (`max_price_zat`) exists only for the duration of `seal_ballot`
//! and is never returned or stored.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tally_crypto::auction::{self, AuctionLog};
use tally_crypto::ballot::{self, Ballot};
use tally_crypto::codec;
use tally_crypto::manifest::{Close, Committee, Endorsement, Manifest, Receipt, MANIFEST_V2};
use tally_crypto::schnorr::Signature;
use tally_zcash::memo::Bond;

thread_local! {
    static OUT: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[no_mangle]
pub extern "C" fn tally_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len);
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// # Safety
/// `ptr` must come from `tally_alloc(len)` and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn tally_free(ptr: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(ptr, 0, len));
}

#[no_mangle]
pub extern "C" fn tally_out_ptr() -> *const u8 {
    OUT.with(|o| o.borrow().as_ptr())
}

#[no_mangle]
pub extern "C" fn tally_out_len() -> usize {
    OUT.with(|o| o.borrow().len())
}

/// Overwrite and drop the last reply (it can hold a ballot key). JS calls
/// this as soon as it has decoded the reply.
#[no_mangle]
pub extern "C" fn tally_clear_out() {
    OUT.with(|o| {
        let mut o = o.borrow_mut();
        wipe(&mut o);
        *o = Vec::new();
    });
}

/// Zero a buffer in a way the optimiser can't drop.
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

/// Read the input, run `f`, store the JSON reply. Takes ownership of the input.
unsafe fn call(ptr: *mut u8, len: usize, f: impl FnOnce(&str) -> Result<Value, String>) {
    let mut input = Vec::from_raw_parts(ptr, len, len);
    let reply = match std::str::from_utf8(&input).map_err(|e| e.to_string()).and_then(f) {
        Ok(v) => json!({ "ok": v }),
        Err(e) => json!({ "err": e }),
    };
    // The input can hold the bid (seal_ballot); don't leave it in linear memory.
    wipe(&mut input);
    tally_clear_out();
    OUT.with(|o| *o.borrow_mut() = reply.to_string().into_bytes());
}

/// Every public check, plus a summary for display.
pub fn verify_log(input: &str) -> Result<Value, String> {
    let log: AuctionLog = serde_json::from_str(input).map_err(|e| format!("not an auction log: {e}"))?;
    let checks = auction::verify(&log);
    let all_ok = checks.iter().all(|c| c.ok);
    let decrypted_totals: Vec<usize> = log
        .decryptions
        .iter()
        .filter_map(|d| d.target.strip_prefix("T_").and_then(|k| k.parse().ok()))
        .collect();
    Ok(json!({
        "all_ok": all_ok,
        "checks": checks,
        "summary": {
            "auction_id": hex::encode(log.manifest.auction_id),
            "supply": log.manifest.supply,
            "ladder_zat": log.manifest.ladder_zat,
            "bond_zat": log.manifest.bond_zat,
            "close_height": log.manifest.close_height,
            "committee": log.manifest.committee.members,
            "threshold": format!("{}-of-{}", log.manifest.committee.key.t, log.manifest.committee.key.n),
            "ballots": log.entries.len(),
            "bonded": log.bonded().len(),
            "closed": log.close.is_some(),
            "root": hex::encode(log.head()),
            "decrypted_totals": decrypted_totals,
            "cells_opened": log.decryptions.iter().filter(|d| d.target.starts_with("ballot:")).count(),
            "result": log.result,
            "settlements": log.settlements.iter().map(|s| json!({"P": codec::point_to_hex(&s.p), "txid": s.txid})).collect::<Vec<_>>(),
        }
    }))
}

#[derive(Deserialize)]
struct SealIn {
    manifest: Manifest,
    max_price_zat: u64,
    seed_hex: String,
}

#[derive(Serialize)]
struct SealOut {
    ballot: Ballot,
    ballot_sk: String,
    #[serde(rename = "P")]
    p: String,
    ballot_hash: String,
    levels_sealed: usize,
}

/// Seal a ballot in the browser. The returned object never contains the
/// bid; `levels_sealed` is the ladder length, not the number of yes cells.
pub fn seal_ballot(input: &str) -> Result<Value, String> {
    let i: SealIn = serde_json::from_str(input).map_err(|e| e.to_string())?;
    let m = &i.manifest;
    // Only v2: the id is the content hash and every member endorsed it.
    m.verify_current().map_err(|e| format!("manifest rejected: {e}"))?;
    let yes = m.ladder_zat.iter().filter(|p| **p <= i.max_price_zat).count();
    if yes == 0 {
        return Err("bid is below the lowest price level".into());
    }
    let seed = codec::bytes32_from_hex(&i.seed_hex).map_err(|_| "seed must be 32 bytes of hex".to_string())?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (b, sk) = Ballot::build(m.auction_id, &m.committee.key.h, m.levels(), yes, &mut rng).map_err(|e| e.to_string())?;
    b.verify(&m.auction_id, &m.committee.key.h, m.levels()).map_err(|e| e.to_string())?;
    let out = SealOut {
        p: codec::point_to_hex(&b.p),
        ballot_hash: hex::encode(b.body_hash()),
        ballot_sk: codec::scalar_to_hex(&sk),
        levels_sealed: m.levels(),
        ballot: b,
    };
    serde_json::to_value(out).map_err(|e| e.to_string())
}

#[derive(Deserialize)]
struct MemoIn {
    auction_id: String,
    ballot_hash: String,
    refund_ua: String,
}

/// The bond memo: plain text (`TLYB1 ...`) and its 512-byte padded hex.
pub fn bond_memo(input: &str) -> Result<Value, String> {
    let i: MemoIn = serde_json::from_str(input).map_err(|e| e.to_string())?;
    tally_zcash::memo::require_orchard_only_ua(&i.refund_ua).map_err(|e| e.to_string())?;
    let bond = Bond {
        auction_id: codec::bytes32_from_hex(&i.auction_id).map_err(|e| e.to_string())?,
        ballot_hash: codec::bytes32_from_hex(&i.ballot_hash).map_err(|e| e.to_string())?,
        refund_ua: i.refund_ua,
    };
    let text = bond.text();
    Ok(json!({ "text": text, "hex": hex::encode(bond.encode().map_err(|e| e.to_string())?) }))
}

#[derive(Deserialize)]
struct ClaimIn {
    ballot_sk: String,
    listing_hash: String,
    seed_hex: String,
}

/// Win claim: a signature by the ballot key over a listing hash.
pub fn sign_claim(input: &str) -> Result<Value, String> {
    let i: ClaimIn = serde_json::from_str(input).map_err(|e| e.to_string())?;
    let b = codec::scalar_from_hex(&i.ballot_sk).map_err(|e| e.to_string())?;
    let seed = codec::bytes32_from_hex(&i.seed_hex).map_err(|e| e.to_string())?;
    let sig = ballot::sign_claim(&b, i.listing_hash.as_bytes(), &mut ChaCha20Rng::from_seed(seed));
    Ok(json!({ "P": codec::point_to_hex(&(tally_crypto::g() * b)), "sig": sig }))
}

#[derive(Deserialize)]
struct ReceiptIn {
    receipt: Receipt,
    bulletin_pk: String,
    auction_id: String,
}

/// Check the bulletin's signed inclusion receipt for our ballot.
pub fn verify_receipt(input: &str) -> Result<Value, String> {
    let i: ReceiptIn = serde_json::from_str(input).map_err(|e| e.to_string())?;
    let pk = codec::point_from_hex(&i.bulletin_pk).map_err(|e| e.to_string())?;
    let id = codec::bytes32_from_hex(&i.auction_id).map_err(|e| e.to_string())?;
    Ok(json!(i.receipt.auction_id == id && i.receipt.verify(&pk)))
}

#[derive(Deserialize)]
struct QrIn {
    text: String,
}

/// A QR code for a payment request, as a self-contained SVG (one path, no
/// styles), so a phone wallet can scan the deposit straight off the page.
pub fn qr_svg(input: &str) -> Result<Value, String> {
    use qrcode::{Color, EcLevel, QrCode};
    let i: QrIn = serde_json::from_str(input).map_err(|e| e.to_string())?;
    let code = QrCode::with_error_correction_level(i.text.as_bytes(), EcLevel::M).map_err(|e| e.to_string())?;
    let w = code.width();
    let q = 4; // quiet zone, in modules
    let mut d = String::new();
    for (k, c) in code.to_colors().iter().enumerate() {
        if *c == Color::Dark {
            d.push_str(&format!("M{} {}h1v1h-1z", k % w + q, k / w + q));
        }
    }
    let n = w + 2 * q;
    Ok(json!(format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" shape-rendering="crispEdges"><rect width="{n}" height="{n}" fill="#fff"/><path fill="#0b1510" d="{d}"/></svg>"##
    )))
}

// ---- seller console ----
// The seller's signing key is made here, handed back once for the seller to
// download, and never sent to the desk. These are the same steps as
// `tally-settle auction-create`, `auction-publish` and `auction-close`.

#[derive(Deserialize)]
struct DraftIn {
    title: String,
    collection_id: String,
    supply: u64,
    step_zat: u64,
    levels: u64,
    bond_zat: u64,
    open_height: u32,
    close_in: u32,
    settle_window: u32,
    min_batch: u64,
    committee: Committee,
    escrow_ua: String,
    forfeit_ua: String,
    seed_hex: String,
}

/// Draft and sign an offering. Returns the draft for the committee to
/// endorse and the seller key record (same shape as the CLI's).
pub fn draft_offering(input: &str) -> Result<Value, String> {
    let i: DraftIn = serde_json::from_str(input).map_err(|e| e.to_string())?;
    for (name, ua) in [("escrow", &i.escrow_ua), ("forfeit", &i.forfeit_ua)] {
        tally_zcash::memo::require_orchard_only_ua(ua).map_err(|_| format!("{name} address must be an unused Orchard-only unified address"))?;
    }
    if i.escrow_ua == i.forfeit_ua {
        return Err("escrow and forfeit addresses must differ".into());
    }
    if i.levels == 0 || i.levels > 64 || i.step_zat == 0 {
        return Err("the price ladder needs 1 to 64 levels and a step above zero".into());
    }
    let seed = codec::bytes32_from_hex(&i.seed_hex).map_err(|_| "seed must be 32 bytes of hex".to_string())?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let seller_sk = tally_crypto::random_scalar(&mut rng);
    let mut m = Manifest {
        v: MANIFEST_V2,
        title: i.title,
        auction_id: [0; 32],
        collection_id: codec::bytes32_from_hex(&i.collection_id).map_err(|_| "collection ID must be 64 hex characters".to_string())?,
        supply: i.supply,
        ladder_zat: (1..=i.levels).map(|k| k * i.step_zat).collect(),
        bond_zat: i.bond_zat,
        open_height: i.open_height,
        close_height: i.open_height + i.close_in,
        settle_window_blocks: i.settle_window,
        min_batch: i.min_batch,
        committee: i.committee,
        escrow_ua: i.escrow_ua,
        forfeit_ua: i.forfeit_ua,
        seller_pk: tally_crypto::g() * seller_sk,
        sig: Signature { r: tally_crypto::g(), s: tally_crypto::Scalar::from(0u64) },
        endorsements: vec![],
    };
    m.bind_id();
    m.sign(&seller_sk, &mut rng);
    m.verify_draft().map_err(|e| e.to_string())?;
    Ok(json!({
        "draft": m,
        "seller_key": { "auction_id": hex::encode(m.auction_id), "seller_sk": codec::scalar_to_hex(&seller_sk) },
    }))
}

#[derive(Deserialize)]
struct PublishIn {
    draft: Manifest,
    endorsements: Vec<Endorsement>,
}

/// Attach the members' endorsements and check the result is publishable.
pub fn attach_endorsements(input: &str) -> Result<Value, String> {
    let i: PublishIn = serde_json::from_str(input).map_err(|e| e.to_string())?;
    let mut m = i.draft;
    m.endorsements = i.endorsements;
    m.endorsements.sort_by_key(|e| e.j);
    m.verify_current().map_err(|e| e.to_string())?;
    serde_json::to_value(m).map_err(|e| e.to_string())
}

#[derive(Deserialize)]
struct CloseIn {
    seller_sk: String,
    log: AuctionLog,
    seed_hex: String,
}

/// Freeze the log at its current head, signed by the seller.
pub fn sign_close(input: &str) -> Result<Value, String> {
    let i: CloseIn = serde_json::from_str(input).map_err(|e| e.to_string())?;
    let sk = codec::scalar_from_hex(&i.seller_sk).map_err(|_| "seller key is not valid".to_string())?;
    if tally_crypto::g() * sk != i.log.manifest.seller_pk {
        return Err("this seller key doesn't belong to this offering".into());
    }
    let seed = codec::bytes32_from_hex(&i.seed_hex).map_err(|_| "seed must be 32 bytes of hex".to_string())?;
    let c = Close::sign(&sk, i.log.manifest.auction_id, i.log.entries.len() as u64, i.log.head(), &mut ChaCha20Rng::from_seed(seed));
    serde_json::to_value(c).map_err(|e| e.to_string())
}

macro_rules! export {
    ($name:ident, $f:path) => {
        /// # Safety
        /// `ptr` must come from `tally_alloc(len)`; ownership passes to this call.
        #[no_mangle]
        pub unsafe extern "C" fn $name(ptr: *mut u8, len: usize) {
            call(ptr, len, $f)
        }
    };
}

export!(tally_verify_log, verify_log);
export!(tally_seal_ballot, seal_ballot);
export!(tally_bond_memo, bond_memo);
export!(tally_sign_claim, sign_claim);
export!(tally_verify_receipt, verify_receipt);
export!(tally_qr_svg, qr_svg);
export!(tally_draft_offering, draft_offering);
export!(tally_attach_endorsements, attach_endorsements);
export!(tally_sign_close, sign_close);
