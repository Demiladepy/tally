//! Auction-side wallet commands: create and close an auction (seller), fund
//! bidder accounts, bid with a bonded ballot (bidder), scan and refund bonds
//! (escrow), and publish settlements (seller).
//!
//! Escrow custody (THREAT_MODEL.md): FROST for Ironwood spends is not usable
//! yet (no public API takes a transaction-supplied randomizer), so the escrow
//! is an ordinary account held by the committee coordinator. It only ever
//! holds bonds, it refunds them to one-time addresses, and forfeits go to a
//! separate address that is never the seller's.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use orchard::keys::Scope;
use pczt::roles::signer::Signer;
use pczt::Pczt;
use serde::{Deserialize, Serialize};
use tally_crypto::auction::{AuctionLog, Settlement};
use tally_crypto::ballot::{self, Ballot};
use tally_crypto::manifest::{Close, Committee, Manifest, Receipt};
use tally_crypto::schnorr::Signature;
use tally_crypto::{codec, g};
use tally_zcash::memo::Bond;
use zcash_client_backend::data_api::wallet::{input_selection::LockFilter, ConfirmationsPolicy};
use zcash_client_backend::data_api::{InputSource, MaxSpendMode, TargetValue, WalletRead};
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::ShieldedPool;

use crate::wallet::{fresh_address, Acct, Received, Wallet, NETWORK};
use crate::{builder, finish_pczt, height, pczt_bytes, rng, zat, zip317_fee};

/// The seller's private auction record (holds the auction signing key).
#[derive(Serialize, Deserialize)]
pub struct SellerAuction {
    pub auction_id: String,
    pub seller_sk: String,
    pub bulletin: String,
}

/// A bidder's private record. It never contains the bid amount.
#[derive(Serialize, Deserialize)]
pub struct BidRecord {
    pub auction_id: String,
    pub bulletin: String,
    pub account: String,
    #[serde(rename = "P")]
    pub p: String,
    /// Ballot secret key b: needed to claim a win. Keep private.
    pub ballot_sk: String,
    pub ballot_hash: String,
    pub receipt: Receipt,
}

#[derive(Serialize, Deserialize)]
pub struct BondsFile {
    pub auction_id: String,
    pub bonds: Vec<BondSeen>,
}

#[derive(Serialize, Deserialize)]
pub struct BondSeen {
    pub ballot_hash: String,
    pub value_zat: u64,
    pub txid: String,
    pub action: u16,
    pub refund_ua: String,
}

/// A win claim the buyer attaches to sale terms.
#[derive(Clone, Serialize, Deserialize)]
pub struct Claim {
    #[serde(rename = "P")]
    pub p: String,
    pub sig: Signature,
}

pub fn ua_for(addr: orchard::Address) -> Result<String> {
    let ua = UnifiedAddress::from_receivers(Some(addr), None, None, None, None).ok_or_else(|| anyhow!("ua"))?;
    Ok(ua.encode(&NETWORK))
}

pub fn orchard_receiver(ua: &str) -> Result<orchard::Address> {
    match Address::decode(&NETWORK, ua) {
        Some(Address::Unified(u)) => u.orchard().copied().ok_or_else(|| anyhow!("address has no Orchard receiver")),
        _ => bail!("not a testnet unified address"),
    }
}

pub fn get_log(bulletin: &str, auction_id: &str) -> Result<AuctionLog> {
    Ok(ureq::get(&format!("{bulletin}/v1/auctions/{auction_id}")).call()?.body_mut().read_json()?)
}

fn post<T: Serialize, R: for<'de> Deserialize<'de>>(url: &str, v: &T) -> Result<R> {
    match ureq::post(url).send_json(v) {
        Ok(mut r) => Ok(r.body_mut().read_json()?),
        Err(ureq::Error::StatusCode(c)) => bail!("bulletin refused: HTTP {c}"),
        Err(e) => Err(e.into()),
    }
}

/// One output of a simple transaction.
struct Out {
    to: orchard::Address,
    value: u64,
    memo: MemoBytes,
}

/// Spend `notes` (all from `payer`), pay `outs`, send change back to `payer`.
fn simple_tx(w: &mut Wallet, identity: &Path, payer: &Acct, notes: Vec<Received>, outs: Vec<Out>) -> Result<Pczt> {
    let ask = w.ask(identity, payer)?;
    let (target, anchor_height) = w.heights()?;
    let fee = zip317_fee(notes.len(), outs.len() + 1);
    let total_in: u64 = notes.iter().map(|n| n.note().value().inner()).sum();
    let total_out: u64 = outs.iter().map(|o| o.value).sum::<u64>() + fee;
    if total_in < total_out {
        bail!("insufficient funds: have {total_in} zat, need {total_out}");
    }
    let mut paths = vec![];
    let mut anchor = None;
    for n in &notes {
        let (a, p) = w.witness(n.note_commitment_tree_position(), anchor_height)?;
        anchor = Some(a);
        paths.push(p);
    }
    let mut b = builder(height(target), anchor.ok_or_else(|| anyhow!("no inputs"))?);
    for (n, p) in notes.iter().zip(paths) {
        b.add_ironwood_spend::<std::convert::Infallible>(payer.fvk.clone(), *n.note(), p)
            .map_err(|e| anyhow!("spend: {e:?}"))?;
    }
    for o in outs {
        b.add_ironwood_output::<std::convert::Infallible>(None, o.to, zat(o.value)?, o.memo)
            .map_err(|e| anyhow!("output: {e:?}"))?;
    }
    b.add_ironwood_output::<std::convert::Infallible>(
        None,
        fresh_address(&payer.fvk, Scope::Internal),
        zat(total_in - total_out)?,
        MemoBytes::empty(),
    )
    .map_err(|e| anyhow!("change: {e:?}"))?;
    let res = b.build_for_pczt(rng(), &zip317::FeeRule::standard()).map_err(|e| anyhow!("build: {e:?}"))?;
    let spend_actions: Vec<usize> = (0..notes.len())
        .map(|i| res.ironwood_meta.spend_action_index(i).ok_or_else(|| anyhow!("metadata")))
        .collect::<Result<_>>()?;
    let mut s = Signer::new(finish_pczt(res)?).map_err(|e| anyhow!("signer: {e:?}"))?;
    for a in spend_actions {
        s.sign_ironwood(rng(), a, &ask).map_err(|e| anyhow!("sign: {e:?}"))?;
    }
    Ok(s.finish())
}

/// All spendable Ironwood notes of an account.
fn all_notes(w: &Wallet, acct: &Acct) -> Result<Vec<Received>> {
    let (target, _) = w.heights()?;
    let notes = w.db.select_spendable_notes(
        acct.uuid,
        TargetValue::AllFunds(MaxSpendMode::MaxSpendable),
        &[ShieldedPool::Ironwood],
        target,
        ConfirmationsPolicy::default(),
        &[],
        LockFilter::Unfiltered,
    )?;
    Ok(notes.ironwood().to_vec())
}

// ---------- seller ----------

#[allow(clippy::too_many_arguments)]
pub fn create(
    seller_wallet: &Path,
    record: &Path,
    committee: &Path,
    escrow_wallet: &Path,
    escrow_account: &str,
    forfeit_account: &str,
    supply: u64,
    ladder: &str,
    bond_zat: u64,
    close_in: u32,
    settle_window: u32,
    min_batch: u64,
    bulletin: &str,
    out: &Path,
) -> Result<()> {
    if out.exists() {
        bail!("{} exists; refusing to overwrite", out.display());
    }
    #[derive(Deserialize)]
    struct MintRec {
        collection_id: String,
    }
    let mint: MintRec = serde_json::from_str(&fs::read_to_string(record)?)?;
    let committee: Committee = serde_json::from_str(&fs::read_to_string(committee)?)?;
    let (step, levels) = ladder.split_once(':').ok_or_else(|| anyhow!("--ladder is step_zat:levels"))?;
    let (step, levels): (u64, u64) = (step.parse()?, levels.parse()?);

    let seller = Wallet::open(seller_wallet)?;
    let (target, _) = seller.heights()?;
    let now = u32::from(height(target));
    let escrow = Wallet::open(escrow_wallet)?;
    let escrow_ua = ua_for(fresh_address(&escrow.account(escrow_account)?.fvk, Scope::External))?;
    let forfeit_ua = ua_for(fresh_address(&escrow.account(forfeit_account)?.fvk, Scope::External))?;

    let mut r6 = rand_core_06::OsRng;
    let seller_sk = tally_crypto::random_scalar(&mut r6);
    let mut auction_id = [0u8; 32];
    rand_core_06::RngCore::fill_bytes(&mut r6, &mut auction_id);
    let mut m = Manifest {
        v: 1,
        auction_id,
        collection_id: codec::bytes32_from_hex(&mint.collection_id).map_err(|e| anyhow!("{e}"))?,
        supply,
        ladder_zat: (1..=levels).map(|i| i * step).collect(),
        bond_zat,
        open_height: now,
        close_height: now + close_in,
        settle_window_blocks: settle_window,
        min_batch,
        committee,
        escrow_ua,
        forfeit_ua,
        seller_pk: g() * seller_sk,
        sig: Signature { r: g(), s: tally_crypto::Scalar::from(0u64) },
    };
    m.sign(&seller_sk, &mut r6);
    m.verify().map_err(|e| anyhow!("{e}"))?;
    let _: AuctionLog = post(&format!("{bulletin}/v1/auctions"), &m)?;
    let rec = SellerAuction {
        auction_id: hex::encode(auction_id),
        seller_sk: codec::scalar_to_hex(&seller_sk),
        bulletin: bulletin.to_string(),
    };
    fs::write(out, serde_json::to_string_pretty(&rec)?)?;
    println!("auction {} open: supply {supply}, {levels} levels of {step} zat, closes at height {}", rec.auction_id, m.close_height);
    Ok(())
}

pub fn close(record: &Path) -> Result<()> {
    let rec: SellerAuction = serde_json::from_str(&fs::read_to_string(record)?)?;
    let sk = codec::scalar_from_hex(&rec.seller_sk).map_err(|e| anyhow!("{e}"))?;
    let log = get_log(&rec.bulletin, &rec.auction_id)?;
    let c = Close::sign(&sk, log.manifest.auction_id, log.entries.len() as u64, log.head(), &mut rand_core_06::OsRng);
    let _: AuctionLog = post(&format!("{}/v1/auctions/{}/close", rec.bulletin, rec.auction_id), &c)?;
    println!("closed with {} entries, root {}", log.entries.len(), hex::encode(log.head()));
    Ok(())
}

pub fn settle_post(record: &Path, p: &str, txid: &str) -> Result<()> {
    let rec: SellerAuction = serde_json::from_str(&fs::read_to_string(record)?)?;
    let sk = codec::scalar_from_hex(&rec.seller_sk).map_err(|e| anyhow!("{e}"))?;
    let id = codec::bytes32_from_hex(&rec.auction_id).map_err(|e| anyhow!("{e}"))?;
    let s = Settlement::sign(&sk, &id, codec::point_from_hex(p).map_err(|e| anyhow!("{e}"))?, txid.to_string(), &mut rand_core_06::OsRng);
    let _: usize = post(&format!("{}/v1/auctions/{}/settlements", rec.bulletin, rec.auction_id), &s)?;
    println!("settlement recorded");
    Ok(())
}

// ---------- bidders ----------

pub fn fund(wallet: &Path, identity: &Path, payer: &str, accounts: &[String], value: u64, out: &Path) -> Result<()> {
    let mut w = Wallet::open(wallet)?;
    let payer = w.account(payer)?;
    let outs = accounts
        .iter()
        .map(|a| Ok(Out { to: fresh_address(&w.account(a)?.fvk, Scope::External), value, memo: MemoBytes::empty() }))
        .collect::<Result<Vec<_>>>()?;
    let (target, _) = w.heights()?;
    let need = value * accounts.len() as u64 + zip317_fee(1, accounts.len() + 1);
    let note = w.funding_note(&payer, need, target)?;
    let p = simple_tx(&mut w, identity, &payer, vec![note], outs)?;
    fs::write(out, pczt_bytes(p)?)?;
    println!("funding PCZT {} ({} accounts × {value} zat)", out.display(), accounts.len());
    Ok(())
}

/// Seal a ballot for `max_price_zat`, post it, and build the bond payment.
/// The bid amount exists only in this process's memory.
pub fn bid(
    wallet: &Path,
    identity: &Path,
    account: &str,
    bulletin: &str,
    auction_id: &str,
    max_price_zat: u64,
    record: &Path,
    out: &Path,
) -> Result<()> {
    if record.exists() {
        bail!("{} exists; one bid per record", record.display());
    }
    let log = get_log(bulletin, auction_id)?;
    let m = &log.manifest;
    m.verify().map_err(|e| anyhow!("manifest: {e}"))?;
    if log.close.is_some() {
        bail!("auction is closed");
    }
    let yes = m.ladder_zat.iter().filter(|p| **p <= max_price_zat).count();
    if yes == 0 {
        bail!("bid is below the lowest price level");
    }

    let mut w = Wallet::open(wallet)?;
    let acct = w.account(account)?;
    let (target, _) = w.heights()?;
    if u32::from(height(target)) >= m.close_height {
        bail!("past the close height");
    }

    let mut r6 = rand_core_06::OsRng;
    let (ballot, b) = Ballot::build(m.auction_id, &m.committee.key.h, m.levels(), yes, &mut r6).map_err(|e| anyhow!("{e}"))?;
    let receipt: Receipt = post(&format!("{bulletin}/v1/auctions/{auction_id}/ballots"), &ballot)?;
    if !receipt.verify(&log.bulletin_pk) || receipt.auction_id != m.auction_id {
        bail!("bulletin returned an invalid receipt; keep the ballot and complain");
    }

    // Bond: escrow gets bond_zat with memo (auction, H(ballot), one-time refund address).
    let refund_ua = ua_for(fresh_address(&acct.fvk, Scope::External))?;
    let bond = Bond { auction_id: m.auction_id, ballot_hash: ballot.body_hash(), refund_ua: refund_ua.clone() };
    let memo = MemoBytes::from_bytes(&bond.encode().map_err(|e| anyhow!("{e}"))?).map_err(|e| anyhow!("{e:?}"))?;
    let fee = zip317_fee(1, 2);
    let note = w.funding_note(&acct, m.bond_zat + fee, target)?;
    let p = simple_tx(&mut w, identity, &acct, vec![note], vec![Out { to: orchard_receiver(&m.escrow_ua)?, value: m.bond_zat, memo }])?;
    fs::write(out, pczt_bytes(p)?)?;

    let rec = BidRecord {
        auction_id: auction_id.to_string(),
        bulletin: bulletin.to_string(),
        account: account.to_string(),
        p: codec::point_to_hex(&ballot.p),
        ballot_sk: codec::scalar_to_hex(&b),
        ballot_hash: hex::encode(ballot.body_hash()),
        receipt,
    };
    fs::write(record, serde_json::to_string_pretty(&rec)?)?;
    println!("ballot #{} sealed and receipted; bond PCZT {}", rec.receipt.i, out.display());
    Ok(())
}

pub fn make_claim(bid_record: &Path, listing_hash: &str) -> Result<Claim> {
    let rec: BidRecord = serde_json::from_str(&fs::read_to_string(bid_record)?)?;
    let b = codec::scalar_from_hex(&rec.ballot_sk).map_err(|e| anyhow!("{e}"))?;
    Ok(Claim { p: rec.p, sig: ballot::sign_claim(&b, listing_hash.as_bytes(), &mut rand_core_06::OsRng) })
}

/// Seller side: the claim is valid, the claimant won, has not settled yet,
/// and the listing price is the clearing price.
pub fn check_claim(log: &AuctionLog, claim: &Claim, listing_hash: &str, price_zat: u64) -> Result<()> {
    let r = log.result.as_ref().ok_or_else(|| anyhow!("auction has no result yet"))?;
    let p = codec::point_from_hex(&claim.p).map_err(|e| anyhow!("{e}"))?;
    if !ballot::verify_claim(&p, listing_hash.as_bytes(), &claim.sig) {
        bail!("win claim signature invalid");
    }
    if !r.winners.contains(&p) {
        bail!("claimant is not a winner");
    }
    if log.settlements.iter().any(|s| s.p == p) {
        bail!("this winner already settled");
    }
    if r.price_zat != Some(price_zat) {
        bail!("listing price is not the clearing price");
    }
    Ok(())
}

// ---------- escrow ----------

pub fn scan_bonds(wallet: &Path, account: &str, auction_id: &str, out: &Path) -> Result<()> {
    let w = Wallet::open(wallet)?;
    let acct = w.account(account)?;
    let want = codec::bytes32_from_hex(auction_id).map_err(|e| anyhow!("{e}"))?;
    let mut bonds = vec![];
    for n in all_notes(&w, &acct)? {
        let Some(memo) = w.memo(*n.txid(), n.output_index() as u32)? else { continue };
        let Ok(b) = Bond::decode(&memo) else { continue };
        if b.auction_id != want {
            continue;
        }
        bonds.push(BondSeen {
            ballot_hash: hex::encode(b.ballot_hash),
            value_zat: n.note().value().inner(),
            txid: n.txid().to_string(),
            action: n.output_index(),
            refund_ua: b.refund_ua,
        });
    }
    let f = BondsFile { auction_id: auction_id.to_string(), bonds };
    fs::write(out, serde_json::to_string_pretty(&f)?)?;
    println!("{} bonds for this auction", f.bonds.len());
    Ok(())
}

/// Refund every bond to its one-time address, except bonds of winners who
/// did not settle in time: those go to the forfeit address, never the seller.
pub fn refund(wallet: &Path, identity: &Path, account: &str, bulletin: &str, bonds: &Path, forfeit_unsettled: bool, out: &Path) -> Result<()> {
    let f: BondsFile = serde_json::from_str(&fs::read_to_string(bonds)?)?;
    let log = get_log(bulletin, &f.auction_id)?;
    let m = &log.manifest;
    let mut w = Wallet::open(wallet)?;
    let acct = w.account(account)?;

    let by_hash: BTreeMap<String, String> = log
        .entries
        .iter()
        .map(|e| (hex::encode(e.ballot.body_hash()), codec::point_to_hex(&e.ballot.p)))
        .collect();
    let unsettled: Vec<String> = match &log.result {
        Some(r) if forfeit_unsettled => r
            .winners
            .iter()
            .filter(|p| !log.settlements.iter().any(|s| &s.p == *p))
            .map(codec::point_to_hex)
            .collect(),
        _ => vec![],
    };
    if forfeit_unsettled && log.result.is_none() {
        bail!("no result yet; can't decide forfeits");
    }

    let mut outs = vec![];
    let (mut refunds, mut forfeits) = (0, 0);
    for b in &f.bonds {
        let forfeit = by_hash.get(&b.ballot_hash).map(|p| unsettled.contains(p)).unwrap_or(false);
        let to = if forfeit { orchard_receiver(&m.forfeit_ua)? } else { orchard_receiver(&b.refund_ua)? };
        if forfeit { forfeits += 1 } else { refunds += 1 }
        outs.push(Out { to, value: b.value_zat, memo: MemoBytes::empty() });
    }
    let notes = all_notes(&w, &acct)?;
    let p = simple_tx(&mut w, identity, &acct, notes, outs).context("escrow needs a small float for the fee")?;
    fs::write(out, pczt_bytes(p)?)?;
    println!("refund PCZT {}: {refunds} refunds, {forfeits} forfeits", out.display());
    Ok(())
}

pub fn block_hash(wallet: &Path, h: u32) -> Result<()> {
    let w = Wallet::open(wallet)?;
    let bh = w.db.get_block_hash(BlockHeight::from(h))?.ok_or_else(|| anyhow!("block {h} not in wallet; sync first"))?;
    println!("{bh}");
    Ok(())
}
