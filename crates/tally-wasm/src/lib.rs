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
use tally_crypto::manifest::{Manifest, Receipt};
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

/// Read the input, run `f`, store the JSON reply. Takes ownership of the input.
unsafe fn call(ptr: *mut u8, len: usize, f: impl FnOnce(&str) -> Result<Value, String>) {
    let input = Vec::from_raw_parts(ptr, len, len);
    let reply = match std::str::from_utf8(&input).map_err(|e| e.to_string()).and_then(f) {
        Ok(v) => json!({ "ok": v }),
        Err(e) => json!({ "err": e }),
    };
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
    m.verify().map_err(|e| format!("manifest rejected: {e}"))?;
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
    if !i.refund_ua.starts_with("u1") && !i.refund_ua.starts_with("utest1") {
        return Err("refund address must be a unified address".into());
    }
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
