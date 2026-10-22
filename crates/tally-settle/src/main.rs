//! tally-settle: mint carrier-note items and settle sales atomically.
//!
//! Every command writes a signed PCZT. Broadcast it with
//! `zcash-devtool -w <wallet> pczt send --input <file>`, which extracts,
//! verifies the proof and signatures, stores and sends the transaction.
//!
//! The sale follows Zarrier's pattern (re-implemented, credited in README):
//! the buyer builds, proves and signs only their own spend; the seller checks
//! the terms, signs the carrier spend last, and broadcasts.

mod wallet;

use std::convert::Infallible;
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use orchard::keys::Scope;
use pczt::roles::{
    creator::Creator, io_finalizer::IoFinalizer, prover::Prover, signer::Signer,
    spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor, verifier::Verifier,
};
use pczt::Pczt;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use serde::{Deserialize, Serialize};
use tally_zcash::memo::Item;
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding, PcztResult};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::TxId;

use wallet::{fresh_address, Wallet, NETWORK};

/// Tries before giving up on getting the carrier spend and its successor
/// output into the same Action (each try succeeds with p ≈ 1/num_actions).
const MAX_BIND_TRIES: usize = 64;
/// Blocks the seller has to accept the buyer's PCZT (25 s blocks after NU7).
const EXPIRY_DELTA: u32 = 120;

#[derive(Parser)]
#[command(about = "Tally: carrier-note mint and atomic PCZT settlement (testnet)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Seller: mint N items as zero-value Ironwood carrier notes.
    Mint {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long, default_value_t = 2)]
        count: u32,
        /// Where to write the mint record (collection key lives here: keep it private).
        #[arg(long)]
        record: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Buyer: build, prove and sign the buyer's half of a sale.
    SaleBuild {
        #[arg(long)]
        seller_wallet: PathBuf,
        #[arg(long)]
        buyer_wallet: PathBuf,
        #[arg(long)]
        buyer_identity: PathBuf,
        /// Mint record from `mint`.
        #[arg(long)]
        record: PathBuf,
        /// Which minted item (0-based).
        #[arg(long)]
        item: u32,
        #[arg(long)]
        price_zat: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Seller: check the buyer's PCZT, sign the carrier spend, write the final PCZT.
    SaleAccept {
        #[arg(long)]
        seller_wallet: PathBuf,
        #[arg(long)]
        seller_identity: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Check a received carrier note: zero value, Tally memo, seller signature,
    /// and (with --terms) that its rho is the nullifier of the note it replaced.
    InspectItem {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        txid: String,
        #[arg(long)]
        action: u32,
        #[arg(long)]
        record: PathBuf,
        #[arg(long)]
        terms: Option<PathBuf>,
    },
    /// Try to extract a transaction from a PCZT (expected to fail if half-signed).
    TryExtract {
        #[arg(long)]
        input: PathBuf,
    },
}

/// Mint record. `collection_sk` is private to the seller; the rest is public.
#[derive(Serialize, Deserialize)]
struct MintRecord {
    collection_id: String,
    collection_sk: String,
    collection_pk: String,
    /// Filled in after broadcast: the mint txid.
    txid: Option<String>,
    items: Vec<MintedItem>,
}

#[derive(Serialize, Deserialize)]
struct MintedItem {
    index: u32,
    /// Ironwood action index of the carrier output in the mint tx.
    action: usize,
    memo_hex: String,
}

/// Terms the buyer commits to, sent alongside the PCZT.
#[derive(Serialize, Deserialize)]
struct SaleTerms {
    carrier_txid: String,
    carrier_action_in_mint: u32,
    carrier_action: usize,
    funding_action: usize,
    carrier_nullifier: String,
    price_zat: u64,
    seller_payout: String,
    expiry_height: u32,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Mint { wallet, identity, count, record, out } => mint(wallet, identity, count, record, out),
        Cmd::SaleBuild { seller_wallet, buyer_wallet, buyer_identity, record, item, price_zat, out } => {
            sale_build(seller_wallet, buyer_wallet, buyer_identity, record, item, price_zat, out)
        }
        Cmd::SaleAccept { seller_wallet, seller_identity, input, out } => {
            sale_accept(seller_wallet, seller_identity, input, out)
        }
        Cmd::InspectItem { wallet, txid, action, record, terms } => inspect_item(wallet, txid, action, record, terms),
        Cmd::TryExtract { input } => {
            let p = Pczt::parse(&fs::read(&input)?).map_err(|e| anyhow!("parse: {e:?}"))?;
            let extracted = SpendFinalizer::new(p)
                .finalize_spends()
                .map_err(|e| anyhow!("{e:?}"))
                .and_then(|p| TransactionExtractor::new(p).extract(UnwrapErr(SysRng)).map_err(|e| anyhow!("{e:?}")));
            match extracted {
                Ok(tx) => {
                    let mut raw = vec![];
                    tx.write(&mut raw)?;
                    fs::write(input.with_extension("tx.hex"), hex::encode(raw))?;
                    println!("EXTRACTED {}", tx.txid());
                    // Everything a public observer can see, by pool.
                    println!("  version          {:?}", tx.version());
                    println!("  transparent      {}", if tx.transparent_bundle().is_some() { "PRESENT" } else { "none" });
                    println!("  sprout           {}", if tx.sprout_bundle().is_some() { "PRESENT" } else { "none" });
                    println!("  sapling          {}", if tx.sapling_bundle().is_some() { "PRESENT" } else { "none" });
                    println!("  orchard          {}", if tx.orchard_bundle().is_some() { "PRESENT" } else { "none" });
                    if let Some(b) = tx.ironwood_bundle() {
                        println!("  ironwood actions {}", b.actions().len());
                        println!("  ironwood balance {} zat (public: the fee leaving the pool)", i64::from(*b.value_balance()));
                    }
                }
                Err(e) => println!("REFUSED {e}"),
            }
            Ok(())
        }
    }
}

fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

/// ZIP 317 conventional fee for an Ironwood-only transaction.
fn zip317_fee(spends: usize, outputs: usize) -> u64 {
    5_000 * spends.max(outputs).max(2) as u64
}

fn zat(v: u64) -> Result<Zatoshis> {
    Zatoshis::from_u64(v).map_err(|_| anyhow!("amount out of range"))
}

fn builder(target: BlockHeight, anchor: orchard::Anchor) -> Builder<zcash_protocol::consensus::Network, ()> {
    Builder::new(
        NETWORK,
        target,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    )
    .with_expiry_height(target + EXPIRY_DELTA)
}

fn proving_key() -> orchard::circuit::ProvingKey {
    orchard::circuit::ProvingKey::build(orchard::bundle::BundleVersion::ironwood_v3().circuit_version())
}

fn finish_pczt(res: PcztResult<zcash_protocol::consensus::Network>) -> Result<Pczt> {
    let p = Creator::build_from_parts(res.pczt_parts).ok_or_else(|| anyhow!("tx version not PCZT-compatible"))?;
    let p = IoFinalizer::new(p).finalize_io(rng()).map_err(|e| anyhow!("io finalize: {e:?}"))?;
    Prover::new(p)
        .create_ironwood_proof(rng(), &proving_key())
        .map_err(|e| anyhow!("prove: {e:?}"))
        .map(|p| p.finish())
}

fn write_pczt(p: Pczt, out: &PathBuf) -> Result<()> {
    fs::write(out, p.serialize().map_err(|e| anyhow!("serialize: {e:?}"))?)?;
    Ok(())
}

fn mint(wallet: PathBuf, identity: PathBuf, count: u32, record: PathBuf, out: PathBuf) -> Result<()> {
    if record.exists() {
        bail!("mint record already exists; refusing to overwrite");
    }
    let mut w = Wallet::open(&wallet)?;
    let keys = w.keys(&identity)?;
    let (target, anchor_height) = w.heights()?;
    let fee = zip317_fee(1, count as usize + 1);
    let fund = w.funding_note(fee, target)?;
    let (anchor, path) = w.witness(fund.note_commitment_tree_position(), anchor_height)?;

    let mut r6 = rand_core_06::OsRng;
    let collection_sk = tally_crypto::random_scalar(&mut r6);
    let mut collection_id = [0u8; 32];
    rand_core_06::RngCore::fill_bytes(&mut r6, &mut collection_id);

    let items: Vec<Item> = (0..count)
        .map(|i| Item::mint(&collection_sk, collection_id, i, vault_art(i), &mut r6))
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!("{e}"))?;

    let mut b = builder(BlockHeight::from(target.saturating_sub(0)), anchor);
    b.add_ironwood_spend::<Infallible>(keys.fvk.clone(), *fund.note(), path)
        .map_err(|e| anyhow!("spend: {e:?}"))?;
    for item in &items {
        let memo = MemoBytes::from_bytes(&item.encode().map_err(|e| anyhow!("{e}"))?).map_err(|e| anyhow!("{e:?}"))?;
        b.add_ironwood_output::<Infallible>(None, fresh_address(&keys.fvk, Scope::External), Zatoshis::ZERO, memo)
            .map_err(|e| anyhow!("output: {e:?}"))?;
    }
    let change = fund.note().value().inner() - fee;
    b.add_ironwood_output::<Infallible>(None, fresh_address(&keys.fvk, Scope::Internal), zat(change)?, MemoBytes::empty())
        .map_err(|e| anyhow!("change: {e:?}"))?;

    let res = b.build_for_pczt(rng(), &zip317::FeeRule::standard()).map_err(|e| anyhow!("build: {e:?}"))?;
    let meta = res.ironwood_meta.clone();
    let fund_action = meta.spend_action_index(0).ok_or_else(|| anyhow!("metadata"))?;
    let minted = items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            Ok(MintedItem {
                index: item.item_index,
                action: meta.output_action_index(i).ok_or_else(|| anyhow!("metadata"))?,
                memo_hex: hex::encode(item.encode().map_err(|e| anyhow!("{e}"))?),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut s = Signer::new(finish_pczt(res)?).map_err(|e| anyhow!("signer: {e:?}"))?;
    s.sign_ironwood(rng(), fund_action, &keys.ask).map_err(|e| anyhow!("sign: {e:?}"))?;
    write_pczt(s.finish(), &out)?;

    let rec = MintRecord {
        collection_id: hex::encode(collection_id),
        collection_sk: tally_crypto::codec::scalar_to_hex(&collection_sk),
        collection_pk: tally_crypto::codec::point_to_hex(&(tally_crypto::g() * collection_sk)),
        txid: None,
        items: minted,
    };
    fs::write(&record, serde_json::to_string_pretty(&rec)?)?;
    println!("minted {count} items into PCZT {}; record {}", out.display(), record.display());
    Ok(())
}

/// 26x26 pixels, 16 colours, 4 bits each = 338 bytes: a vault door whose
/// dial position depends on the item index.
fn vault_art(index: u32) -> Vec<u8> {
    let mut px = [0u8; 26 * 26];
    for y in 0..26i32 {
        for x in 0..26i32 {
            let (dx, dy) = (x - 13, y - 13);
            let r2 = dx * dx + dy * dy;
            px[(y * 26 + x) as usize] = match r2 {
                0..=9 => 15,
                10..=36 => 9,
                37..=100 => 2 + ((index as i32 + dx.abs() + dy.abs()) % 3) as u8,
                101..=144 => 1,
                _ => 0,
            };
        }
    }
    px.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
}

#[allow(clippy::too_many_arguments)]
fn sale_build(
    seller_wallet: PathBuf,
    buyer_wallet: PathBuf,
    buyer_identity: PathBuf,
    record: PathBuf,
    item: u32,
    price_zat: u64,
    out: PathBuf,
) -> Result<()> {
    let rec: MintRecord = serde_json::from_str(&fs::read_to_string(&record)?)?;
    let minted = rec.items.iter().find(|i| i.index == item).ok_or_else(|| anyhow!("unknown item"))?;
    let mint_txid = TxId::from_hex(rec.txid.as_deref().ok_or_else(|| anyhow!("mint record has no txid yet"))?)
        .ok_or_else(|| anyhow!("bad txid"))?;
    let mut memo = [0u8; 512];
    memo.copy_from_slice(&hex::decode(&minted.memo_hex)?);
    let item_memo = Item::decode(&memo).map_err(|e| anyhow!("{e}"))?;

    // In production the seller hands the buyer the carrier note and its
    // witness (scoped to that note). Here both wallets are local.
    let mut seller = Wallet::open(&seller_wallet)?;
    let seller_fvk = seller.fvk()?;
    let mut buyer = Wallet::open(&buyer_wallet)?;
    let buyer_keys = buyer.keys(&buyer_identity)?;

    let (s_target, s_anchor) = seller.heights()?;
    let (b_target, b_anchor) = buyer.heights()?;
    let anchor_height = s_anchor.min(b_anchor);
    let target = BlockHeight::from(s_target.saturating_sub(0)).max(BlockHeight::from(b_target.saturating_sub(0)));

    let carrier = seller.note(mint_txid, minted.action as u32, s_target)?;
    if carrier.note().value().inner() != 0 {
        bail!("carrier note is not zero-value");
    }
    let fee = zip317_fee(2, 3);
    let fund = buyer.funding_note(price_zat + fee, b_target)?;
    let (anchor_s, carrier_path) = seller.witness(carrier.note_commitment_tree_position(), anchor_height)?;
    let (anchor_b, fund_path) = buyer.witness(fund.note_commitment_tree_position(), anchor_height)?;
    if anchor_s != anchor_b {
        bail!("seller and buyer disagree on the Ironwood anchor; sync both wallets");
    }

    let next_memo = MemoBytes::from_bytes(&item_memo.next_hop().encode().map_err(|e| anyhow!("{e}"))?)
        .map_err(|e| anyhow!("{e:?}"))?;
    let carrier_to = fresh_address(&buyer_keys.fvk, Scope::External);
    let payout = fresh_address(&seller_fvk, Scope::External);
    let change = fund.note().value().inner() - price_zat - fee;
    let change_to = fresh_address(&buyer_keys.fvk, Scope::Internal);

    for attempt in 1..=MAX_BIND_TRIES {
        let mut b = builder(target, anchor_s);
        // Spend 0 = carrier, output 0 = its successor: these must share an Action.
        b.add_ironwood_spend::<Infallible>(seller_fvk.clone(), *carrier.note(), carrier_path.clone())
            .map_err(|e| anyhow!("carrier spend: {e:?}"))?;
        b.add_ironwood_spend::<Infallible>(buyer_keys.fvk.clone(), *fund.note(), fund_path.clone())
            .map_err(|e| anyhow!("funding spend: {e:?}"))?;
        b.add_ironwood_output::<Infallible>(None, carrier_to, Zatoshis::ZERO, next_memo.clone())
            .map_err(|e| anyhow!("carrier output: {e:?}"))?;
        b.add_ironwood_output::<Infallible>(None, payout, zat(price_zat)?, MemoBytes::empty())
            .map_err(|e| anyhow!("payout: {e:?}"))?;
        b.add_ironwood_output::<Infallible>(None, change_to, zat(change)?, MemoBytes::empty())
            .map_err(|e| anyhow!("change: {e:?}"))?;

        let res = b.build_for_pczt(rng(), &zip317::FeeRule::standard()).map_err(|e| anyhow!("build: {e:?}"))?;
        let m = &res.ironwood_meta;
        let carrier_action = m.spend_action_index(0).ok_or_else(|| anyhow!("metadata"))?;
        if m.output_action_index(0) != Some(carrier_action) {
            continue;
        }
        let funding_action = m.spend_action_index(1).ok_or_else(|| anyhow!("metadata"))?;
        eprintln!("bound carrier spend and successor in action {carrier_action} (attempt {attempt})");

        let p = finish_pczt(res)?;
        let expiry = u32::from(*p.global().expiry_height());
        let mut s = Signer::new(p).map_err(|e| anyhow!("signer: {e:?}"))?;
        s.sign_ironwood(rng(), funding_action, &buyer_keys.ask).map_err(|e| anyhow!("sign: {e:?}"))?;
        write_pczt(s.finish(), &out)?;

        let terms = SaleTerms {
            carrier_txid: mint_txid.to_string(),
            carrier_action_in_mint: minted.action as u32,
            carrier_action,
            funding_action,
            carrier_nullifier: hex::encode(carrier.note().nullifier(&seller_fvk).to_bytes()),
            price_zat,
            seller_payout: hex::encode(payout.to_raw_address_bytes()),
            expiry_height: expiry,
        };
        fs::write(out.with_extension("terms.json"), serde_json::to_string_pretty(&terms)?)?;
        println!("buyer-signed PCZT {} (expires at height {expiry})", out.display());
        return Ok(());
    }
    bail!("could not bind carrier spend and successor after {MAX_BIND_TRIES} tries")
}

fn sale_accept(seller_wallet: PathBuf, seller_identity: PathBuf, input: PathBuf, out: PathBuf) -> Result<()> {
    let terms: SaleTerms = serde_json::from_str(&fs::read_to_string(input.with_extension("terms.json"))?)
        .context("read sale terms")?;
    let seller = Wallet::open(&seller_wallet)?;
    let keys = seller.keys(&seller_identity)?;
    let (target, _) = seller.heights()?;

    // The seller recomputes what it is giving up from its own wallet.
    let txid = TxId::from_hex(&terms.carrier_txid).ok_or_else(|| anyhow!("bad txid"))?;
    let carrier = seller.note(txid, terms.carrier_action_in_mint, target)?;
    let carrier_nf = carrier.note().nullifier(&keys.fvk).to_bytes();
    let payout_bytes: [u8; 43] = hex::decode(&terms.seller_payout)?
        .try_into()
        .map_err(|_| anyhow!("bad payout address"))?;
    let payout = Option::<orchard::Address>::from(orchard::Address::from_raw_address_bytes(&payout_bytes))
        .ok_or_else(|| anyhow!("bad payout address"))?;
    let ivk = keys.fvk.to_ivk(Scope::External);
    if ivk.diversifier_index(&payout).is_none() {
        bail!("payout address is not ours");
    }

    let p = Pczt::parse(&fs::read(&input)?).map_err(|e| anyhow!("parse: {e:?}"))?;
    if u32::from(*p.global().expiry_height()) <= u32::from(BlockHeight::from(target.saturating_sub(0))) {
        bail!("PCZT expired");
    }
    let mut checked = false;
    let p = Verifier::new(p)
        .with_ironwood::<Infallible, _>(|bundle| {
            let acts = bundle.actions();
            let carrier_ok = acts
                .get(terms.carrier_action)
                .map(|a| a.spend().nullifier().to_bytes() == carrier_nf)
                .unwrap_or(false);
            let paid = acts.iter().any(|a| {
                a.output().recipient().as_ref() == Some(&payout)
                    && a.output().value().map(|v| v.inner()) == Some(terms.price_zat)
            });
            checked = carrier_ok && paid;
            Ok(())
        })
        .map_err(|e| anyhow!("verify: {e:?}"))?
        .finish();
    if !checked {
        bail!("PCZT does not spend our carrier in the agreed action, or does not pay the agreed price to our address");
    }

    let mut s = Signer::new(p).map_err(|e| anyhow!("signer: {e:?}"))?;
    s.sign_ironwood(rng(), terms.carrier_action, &keys.ask).map_err(|e| anyhow!("sign: {e:?}"))?;
    write_pczt(s.finish(), &out)?;
    println!("seller-signed PCZT {}; broadcast with zcash-devtool pczt send", out.display());
    Ok(())
}

fn inspect_item(wallet: PathBuf, txid: String, action: u32, record: PathBuf, terms: Option<PathBuf>) -> Result<()> {
    let rec: MintRecord = serde_json::from_str(&fs::read_to_string(&record)?)?;
    let w = Wallet::open(&wallet)?;
    let (target, _) = w.heights()?;
    let txid = TxId::from_hex(&txid).ok_or_else(|| anyhow!("bad txid"))?;
    let n = w.note(txid, action, target)?;
    let note = n.note();
    let memo_bytes = w
        .memo(txid, action)?
        .ok_or_else(|| anyhow!("no memo stored for this note"))?;
    let item = Item::decode(&memo_bytes).map_err(|e| anyhow!("{e}"))?;
    let pk = tally_crypto::codec::point_from_hex(&rec.collection_pk).map_err(|e| anyhow!("{e}"))?;
    println!("value_zat      {}", note.value().inner());
    println!("collection     {}", hex::encode(item.collection_id));
    println!("item_index     {}", item.item_index);
    println!("hop            {}", item.hop);
    println!("collection_ok  {}", hex::encode(item.collection_id) == rec.collection_id);
    println!("seller_sig_ok  {}", item.verify_seller(&pk).is_ok());
    if let Some(t) = terms {
        let t: SaleTerms = serde_json::from_str(&fs::read_to_string(t)?)?;
        println!("rho==prev_nf   {}", hex::encode(note.rho().to_bytes()) == t.carrier_nullifier);
    }
    Ok(())
}
