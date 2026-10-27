//! tally-settle: mint carrier-note items and settle sales atomically.
//!
//! Flow (seller S, buyer B; only files cross between them):
//!   S: mint        -> carriers land in per-item vault accounts
//!   S: list        -> listing.json (vault viewing key, note, witness, price, payout)
//!   B: sale-build  -> builds from the listing alone, proves, signs its own
//!                     spend, redacts, writes sale.pczt + sale.terms.json
//!   S: sale-accept -> checks terms against its listing, signs the carrier last
//!   S: zcash-devtool pczt send-without-storing sale-final.pczt
//!
//! The sale follows Zarrier's pattern (re-implemented, credited in README).

mod auction;
mod listing;
mod wallet;

use std::convert::Infallible;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use orchard::keys::Scope;
use pczt::roles::{
    creator::Creator, io_finalizer::IoFinalizer, prover::Prover, redactor::Redactor, signer::Signer,
    spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor, verifier::Verifier,
};
use pczt::Pczt;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use serde::{Deserialize, Serialize};
use tally_zcash::memo::Item;
use zcash_client_backend::data_api::{Account, WalletRead};
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding, PcztResult};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::TxId;

use listing::{Carrier, Listing, ListingRest, SaleTerms};
use wallet::{fresh_address, network, Acct, Wallet};

/// Tries before giving up on getting the carrier spend and its successor
/// output into the same Action (each try succeeds with p ≈ 1/num_actions).
const MAX_BIND_TRIES: usize = 64;
/// Expiry delta every standard wallet uses at `target` (ZIP 203 / ZIP 218):
/// 40 blocks before NU7, 120 after, ~50 minutes either way. Using anything
/// else would make Tally's transactions stand out on chain.
fn expiry_delta(target: BlockHeight) -> u32 {
    zcash_primitives::transaction::builder::default_tx_expiry_delta(BranchId::for_height(&network(), target))
}
/// Blocks a listing stays valid; the buyer's witness must exist at its anchor.
const LISTING_TTL: u32 = 80;

#[derive(Parser)]
#[command(about = "Tally: carrier-note mint and atomic PCZT settlement (testnet or mainnet, per wallet)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Seller: mint one item per vault account as zero-value Ironwood carrier notes.
    Mint {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        /// Account that pays the fee.
        #[arg(long)]
        payer: String,
        /// One fresh vault account per item, comma-separated.
        #[arg(long, value_delimiter = ',')]
        vaults: Vec<String>,
        /// Mint record (holds the collection signing key: keep private).
        #[arg(long)]
        record: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Seller: write a listing for one item. View-only; needs no identity.
    List {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        record: PathBuf,
        #[arg(long)]
        item: u32,
        /// Fresh account that receives this sale's payment.
        #[arg(long)]
        payout_account: String,
        #[arg(long)]
        price_zat: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Buyer: build from a listing, prove, sign own spend, redact.
    SaleBuild {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        /// Account that pays.
        #[arg(long)]
        payer: String,
        /// Fresh vault account that receives the item.
        #[arg(long)]
        receive_account: String,
        #[arg(long)]
        listing: PathBuf,
        /// Auction bid record, to claim a won item.
        #[arg(long)]
        claim: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Seller: check the buyer's PCZT against the listing, sign the carrier last.
    SaleAccept {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        listing: PathBuf,
        #[arg(long)]
        input: PathBuf,
        /// Auction log URL: require a valid win claim at the clearing price.
        #[arg(long)]
        auction_log: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Check a received carrier: zero value, Tally memo, seller signature, and
    /// (with --listing) that its rho is the nullifier of the listed note.
    InspectItem {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        txid: String,
        #[arg(long)]
        action: u32,
        #[arg(long)]
        collection_pk: String,
        #[arg(long)]
        listing: Option<PathBuf>,
    },
    /// Seller: open an auction on the bulletin (writes the private auction record).
    AuctionCreate {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        record: PathBuf,
        #[arg(long)]
        committee: PathBuf,
        #[arg(long)]
        escrow_wallet: PathBuf,
        #[arg(long)]
        escrow_account: String,
        #[arg(long)]
        forfeit_account: String,
        #[arg(long)]
        supply: u64,
        /// Offering name shown to bidders, e.g. "Genesis Lot 001" (signed with the terms).
        #[arg(long, default_value = "")]
        title: String,
        /// step_zat:levels, e.g. 100000:16 for 0.001 to 0.016 ZEC.
        #[arg(long)]
        ladder: String,
        #[arg(long)]
        bond_zat: u64,
        /// Blocks until close.
        #[arg(long)]
        close_in: u32,
        #[arg(long, default_value_t = 240)]
        settle_window: u32,
        #[arg(long, default_value_t = 5)]
        min_batch: u64,
        #[arg(long)]
        bulletin: String,
        /// The unendorsed manifest, for the committee to endorse.
        #[arg(long)]
        draft: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Seller: attach every committee member's endorsement and open the auction.
    AuctionPublish {
        #[arg(long)]
        auction: PathBuf,
        #[arg(long)]
        draft: PathBuf,
        #[arg(long, value_delimiter = ',')]
        endorsements: Vec<PathBuf>,
    },
    /// Seller: freeze the log at its current head.
    AuctionClose {
        #[arg(long)]
        auction: PathBuf,
    },
    /// Seller: publish a signed settlement for a winner.
    SettlePost {
        #[arg(long)]
        auction: PathBuf,
        #[arg(long)]
        p: String,
        #[arg(long)]
        txid: String,
    },
    /// Send value_zat to a fresh address of each named account.
    Fund {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        payer: String,
        #[arg(long, value_delimiter = ',')]
        accounts: Vec<String>,
        #[arg(long)]
        value_zat: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Bidder: seal a ballot, post it, and build the bond payment.
    Bid {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        account: String,
        #[arg(long)]
        bulletin: String,
        #[arg(long)]
        auction_id: String,
        #[arg(long)]
        max_price_zat: u64,
        /// Private bid record (ballot key; never the amount).
        #[arg(long)]
        record: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Escrow: list this auction's bonds from the escrow account's memos.
    ScanBonds {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        account: String,
        #[arg(long)]
        auction_id: String,
        /// For the committee: ballot hashes and amounts only.
        #[arg(long)]
        out: PathBuf,
        /// Escrow-only: adds refund addresses and txids. Keep private.
        #[arg(long)]
        escrow_out: PathBuf,
    },
    /// Escrow: refund bonds (forfeiting unsettled winners' bonds if asked).
    Refund {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        account: String,
        #[arg(long)]
        bulletin: String,
        #[arg(long)]
        bonds: PathBuf,
        #[arg(long)]
        forfeit_unsettled: bool,
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the block hash at a height (from the wallet's synced chain).
    BlockHash {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        height: u32,
    },
    /// After broadcasting, record the transaction in each involved wallet so
    /// it knows its notes are spent right away (instead of after the next
    /// sync) and never picks them again for another transaction.
    Record {
        #[arg(long, required = true)]
        wallet: Vec<PathBuf>,
        #[arg(long)]
        input: PathBuf,
    },
    /// Prove an age identity decrypts this wallet's seed and derives the named
    /// account's keys. Prints only OK or an error; never key material.
    CheckIdentity {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        account: String,
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
    vault: String,
    /// Ironwood action index of the carrier output in the mint tx.
    action: usize,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Mint { wallet, identity, payer, vaults, record, out } => mint(&wallet, &identity, &payer, &vaults, &record, &out),
        Cmd::List { wallet, record, item, payout_account, price_zat, out } => {
            list(&wallet, &record, item, &payout_account, price_zat, &out)
        }
        Cmd::SaleBuild { wallet, identity, payer, receive_account, listing, claim, out } => {
            sale_build(&wallet, &identity, &payer, &receive_account, &listing, claim.as_deref(), &out)
        }
        Cmd::SaleAccept { wallet, identity, listing, input, auction_log, out } => {
            sale_accept(&wallet, &identity, &listing, &input, auction_log.as_deref(), &out)
        }
        Cmd::AuctionCreate {
            wallet,
            record,
            committee,
            escrow_wallet,
            escrow_account,
            forfeit_account,
            supply,
            title,
            ladder,
            bond_zat,
            close_in,
            settle_window,
            min_batch,
            bulletin,
            draft,
            out,
        } => auction::create(
            &wallet, &record, &committee, &escrow_wallet, &escrow_account, &forfeit_account, supply, &title, &ladder,
            bond_zat, close_in, settle_window, min_batch, &bulletin, &draft, &out,
        ),
        Cmd::AuctionPublish { auction, draft, endorsements } => auction::publish(&auction, &draft, &endorsements),
        Cmd::AuctionClose { auction } => auction::close(&auction),
        Cmd::SettlePost { auction, p, txid } => auction::settle_post(&auction, &p, &txid),
        Cmd::Fund { wallet, identity, payer, accounts, value_zat, out } => {
            auction::fund(&wallet, &identity, &payer, &accounts, value_zat, &out)
        }
        Cmd::Bid { wallet, identity, account, bulletin, auction_id, max_price_zat, record, out } => {
            auction::bid(&wallet, &identity, &account, &bulletin, &auction_id, max_price_zat, &record, &out)
        }
        Cmd::ScanBonds { wallet, account, auction_id, out, escrow_out } => {
            auction::scan_bonds(&wallet, &account, &auction_id, &out, &escrow_out)
        }
        Cmd::Refund { wallet, identity, account, bulletin, bonds, forfeit_unsettled, out } => {
            auction::refund(&wallet, &identity, &account, &bulletin, &bonds, forfeit_unsettled, &out)
        }
        Cmd::BlockHash { wallet, height } => auction::block_hash(&wallet, height),
        Cmd::InspectItem { wallet, txid, action, collection_pk, listing } => {
            inspect_item(&wallet, &txid, action, &collection_pk, listing.as_deref())
        }
        Cmd::TryExtract { input } => try_extract(&input),
        Cmd::CheckIdentity { wallet, identity, account } => {
            let w = Wallet::open(&wallet)?;
            let acct = w.account(&account)?;
            w.ask(&identity, &acct)?;
            println!("OK: {} decrypts the seed and matches account '{account}' ({:?})", identity.display(), network());
            Ok(())
        }
        Cmd::Record { wallet, input } => record(&wallet, &input),
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

fn txid(s: &str) -> Result<TxId> {
    TxId::from_hex(s).ok_or_else(|| anyhow!("bad txid"))
}

fn height(t: zcash_client_backend::data_api::wallet::TargetHeight) -> BlockHeight {
    t.saturating_sub(0)
}

fn builder(target: BlockHeight, anchor: orchard::Anchor) -> Builder<Network, ()> {
    Builder::new(
        network(),
        target,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    )
    // Builder::new already applies the wallet-default expiry for `target`.
}

fn memo(item: &Item) -> Result<MemoBytes> {
    MemoBytes::from_bytes(&item.encode().map_err(|e| anyhow!("{e}"))?).map_err(|e| anyhow!("{e:?}"))
}

fn proving_key() -> orchard::circuit::ProvingKey {
    orchard::circuit::ProvingKey::build(orchard::bundle::BundleVersion::ironwood_v3().circuit_version())
}

fn finish_pczt(res: PcztResult<Network>) -> Result<Pczt> {
    let p = Creator::build_from_parts(res.pczt_parts).ok_or_else(|| anyhow!("tx version not PCZT-compatible"))?;
    let p = IoFinalizer::new(p).finalize_io(rng()).map_err(|e| anyhow!("io finalize: {e:?}"))?;
    Prover::new(p)
        .create_ironwood_proof(rng(), &proving_key())
        .map_err(|e| anyhow!("prove: {e:?}"))
        .map(|p| p.finish())
}

fn pczt_bytes(p: Pczt) -> Result<Vec<u8>> {
    p.serialize().map_err(|e| anyhow!("serialize: {e:?}"))
}

fn parse_pczt(b: &[u8]) -> Result<Pczt> {
    Pczt::parse(b).map_err(|e| anyhow!("parse PCZT: {e:?}"))
}

fn extract(p: Pczt) -> Result<zcash_primitives::transaction::Transaction> {
    let p = SpendFinalizer::new(p).finalize_spends().map_err(|e| anyhow!("{e:?}"))?;
    TransactionExtractor::new(p).extract(rng()).map_err(|e| anyhow!("{e:?}"))
}

fn mint(wallet: &Path, identity: &Path, payer: &str, vaults: &[String], record: &Path, out: &Path) -> Result<()> {
    if record.exists() {
        bail!("mint record already exists; refusing to overwrite");
    }
    if vaults.is_empty() {
        bail!("need at least one vault account");
    }
    let mut w = Wallet::open(wallet)?;
    let payer = w.account(payer)?;
    let vault_fvks = vaults.iter().map(|v| w.account(v).map(|a| a.fvk)).collect::<Result<Vec<_>>>()?;
    let ask = w.ask(identity, &payer)?;
    let (target, anchor_height) = w.heights()?;
    let fee = zip317_fee(1, vaults.len() + 1);
    let fund = w.funding_note(&payer, fee, target)?;
    let (anchor, path) = w.witness(fund.note_commitment_tree_position(), anchor_height)?;

    let mut r6 = rand_core_06::OsRng;
    let collection_sk = tally_crypto::random_scalar(&mut r6);
    let mut collection_id = [0u8; 32];
    rand_core_06::RngCore::fill_bytes(&mut r6, &mut collection_id);

    let mut b = builder(height(target), anchor);
    b.add_ironwood_spend::<Infallible>(payer.fvk.clone(), *fund.note(), path)
        .map_err(|e| anyhow!("spend: {e:?}"))?;
    for (i, vfvk) in vault_fvks.iter().enumerate() {
        let item = Item::mint(&collection_sk, collection_id, i as u32, vault_art(i as u32), &mut r6).map_err(|e| anyhow!("{e}"))?;
        b.add_ironwood_output::<Infallible>(None, fresh_address(vfvk, Scope::External), Zatoshis::ZERO, memo(&item)?)
            .map_err(|e| anyhow!("output: {e:?}"))?;
    }
    let change = fund.note().value().inner() - fee;
    b.add_ironwood_output::<Infallible>(None, fresh_address(&payer.fvk, Scope::Internal), zat(change)?, MemoBytes::empty())
        .map_err(|e| anyhow!("change: {e:?}"))?;

    let res = b.build_for_pczt(rng(), &zip317::FeeRule::standard()).map_err(|e| anyhow!("build: {e:?}"))?;
    let meta = res.ironwood_meta.clone();
    let fund_action = meta.spend_action_index(0).ok_or_else(|| anyhow!("metadata"))?;
    let items = vaults
        .iter()
        .enumerate()
        .map(|(i, v)| {
            Ok(MintedItem {
                index: i as u32,
                vault: v.clone(),
                action: meta.output_action_index(i).ok_or_else(|| anyhow!("metadata"))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut s = Signer::new(finish_pczt(res)?).map_err(|e| anyhow!("signer: {e:?}"))?;
    s.sign_ironwood(rng(), fund_action, &ask).map_err(|e| anyhow!("sign: {e:?}"))?;
    fs::write(out, pczt_bytes(s.finish())?)?;

    let rec = MintRecord {
        collection_id: hex::encode(collection_id),
        collection_sk: tally_crypto::codec::scalar_to_hex(&collection_sk),
        collection_pk: tally_crypto::codec::point_to_hex(&(tally_crypto::g() * collection_sk)),
        txid: None,
        items,
    };
    fs::write(record, serde_json::to_string_pretty(&rec)?)?;
    println!("minted {} items into {}; record {}", vaults.len(), out.display(), record.display());
    Ok(())
}

/// 26x26 pixels, 16 colours, 4 bits each = 338 bytes: a vault door whose
/// dial pattern depends on the item index.
fn vault_art(index: u32) -> Vec<u8> {
    let mut px = [0u8; 26 * 26];
    for y in 0..26i32 {
        for x in 0..26i32 {
            let (dx, dy) = (x - 13, y - 13);
            px[(y * 26 + x) as usize] = match dx * dx + dy * dy {
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

fn list(wallet: &Path, record: &Path, item: u32, payout_account: &str, price_zat: u64, out: &Path) -> Result<()> {
    let rec: MintRecord = serde_json::from_str(&fs::read_to_string(record)?)?;
    let minted = rec.items.iter().find(|i| i.index == item).ok_or_else(|| anyhow!("unknown item"))?;
    let mint_txid = rec.txid.as_deref().ok_or_else(|| anyhow!("mint record has no txid yet"))?;

    let mut w = Wallet::open(wallet)?;
    let vault = w.account(&minted.vault)?;
    let payout = fresh_address(&w.account(payout_account)?.fvk, Scope::External);
    let (target, anchor_height) = w.heights()?;
    let n = w.note(txid(mint_txid)?, minted.action as u32, target)?;
    let (anchor, path) = w.witness(n.note_commitment_tree_position(), anchor_height)?;
    let memo = w
        .memo(txid(mint_txid)?, minted.action as u32)?
        .ok_or_else(|| anyhow!("carrier memo not in wallet; run `zcash-devtool wallet enhance`"))?;
    let carrier = Carrier {
        fvk: vault.fvk,
        note: *n.note(),
        path,
        anchor,
        item: Item::decode(&memo).map_err(|e| anyhow!("{e}"))?,
    };
    let l = Listing::new_from(
        &carrier,
        ListingRest {
            carrier_txid: mint_txid.to_string(),
            carrier_action: minted.action as u32,
            anchor_height: u32::from(anchor_height),
            collection_pk: rec.collection_pk.clone(),
            price_zat,
            payout,
            valid_until: u32::from(height(target)) + LISTING_TTL,
        },
    )?;
    l.carrier().context("self-check of the new listing failed")?;
    fs::write(out, serde_json::to_string_pretty(&l)?)?;
    println!("listing {} (valid until height {})", out.display(), l.valid_until);
    Ok(())
}

fn sale_build(
    wallet: &Path,
    identity: &Path,
    payer: &str,
    receive_account: &str,
    listing: &Path,
    claim: Option<&Path>,
    out: &Path,
) -> Result<()> {
    let l: Listing = serde_json::from_str(&fs::read_to_string(listing)?)?;
    let c = l.carrier().context("listing rejected")?;
    let payout = l.payout()?;

    let mut w = Wallet::open(wallet)?;
    let payer = w.account(payer)?;
    let receive = w.account(receive_account)?;
    let ask = w.ask(identity, &payer)?;
    let (target, _) = w.heights()?;
    if u32::from(height(target)) > l.valid_until {
        bail!("listing expired");
    }

    // The anchor must be a real chain state, not one the seller made up.
    let anchor_height = BlockHeight::from(l.anchor_height);
    let fee = zip317_fee(2, 3);
    let fund = w.funding_note(&payer, l.price_zat + fee, target)?;
    let (our_anchor, fund_path) = w.witness(fund.note_commitment_tree_position(), anchor_height)?;
    if our_anchor != c.anchor {
        bail!("listing anchor does not match our view of the chain at height {anchor_height}");
    }

    let target = height(target);
    let carrier_to = fresh_address(&receive.fvk, Scope::External);
    let change = fund.note().value().inner() - l.price_zat - fee;
    let change_to = fresh_address(&payer.fvk, Scope::Internal);
    let next = memo(&c.item.next_hop())?;
    let expiry_cap = l.valid_until.min(u32::from(target) + expiry_delta(target));

    for attempt in 1..=MAX_BIND_TRIES {
        let mut b = builder(target, c.anchor).with_expiry_height(BlockHeight::from(expiry_cap));
        // Spend 0 = carrier, output 0 = its successor: these must share an Action.
        b.add_ironwood_spend::<Infallible>(c.fvk.clone(), c.note, c.path.clone())
            .map_err(|e| anyhow!("carrier spend: {e:?}"))?;
        b.add_ironwood_spend::<Infallible>(payer.fvk.clone(), *fund.note(), fund_path.clone())
            .map_err(|e| anyhow!("funding spend: {e:?}"))?;
        b.add_ironwood_output::<Infallible>(None, carrier_to, Zatoshis::ZERO, next.clone())
            .map_err(|e| anyhow!("carrier output: {e:?}"))?;
        b.add_ironwood_output::<Infallible>(None, payout, zat(l.price_zat)?, MemoBytes::empty())
            .map_err(|e| anyhow!("payout: {e:?}"))?;
        b.add_ironwood_output::<Infallible>(None, change_to, zat(change)?, MemoBytes::empty())
            .map_err(|e| anyhow!("change: {e:?}"))?;

        let res = b.build_for_pczt(rng(), &zip317::FeeRule::standard()).map_err(|e| anyhow!("build: {e:?}"))?;
        let m = &res.ironwood_meta;
        let ca = m.spend_action_index(0).ok_or_else(|| anyhow!("metadata"))?;
        if m.output_action_index(0) != Some(ca) {
            continue;
        }
        let fa = m.spend_action_index(1).ok_or_else(|| anyhow!("metadata"))?;
        let pa = m.output_action_index(1).ok_or_else(|| anyhow!("metadata"))?;
        let xa = m.output_action_index(2).ok_or_else(|| anyhow!("metadata"))?;
        eprintln!("bound carrier spend and successor in action {ca} (attempt {attempt})");

        let p = finish_pczt(res)?;
        let expiry = u32::from(*p.global().expiry_height());
        let mut s = Signer::new(p).map_err(|e| anyhow!("signer: {e:?}"))?;
        s.sign_ironwood(rng(), fa, &ask).map_err(|e| anyhow!("sign: {e:?}"))?;

        // Strip everything about the buyer that the seller doesn't need: the
        // funding note, its key and witness, where the item goes, and change.
        let p = Redactor::new(s.finish())
            .redact_ironwood_with(|mut r| {
                r.redact_action(fa, |mut a| {
                    a.clear_spend_fvk();
                    a.clear_spend_witness();
                    a.clear_spend_zip32_derivation();
                    a.clear_spend_recipient();
                    a.clear_spend_value();
                    a.clear_spend_rho();
                    a.clear_spend_rseed();
                    a.clear_spend_alpha();
                    a.clear_spend_proprietary();
                });
                for oa in [ca, xa] {
                    r.redact_action(oa, |mut a| {
                        a.clear_output_recipient();
                        a.clear_output_value();
                        a.clear_output_rseed();
                        a.clear_output_ock();
                        a.clear_output_zip32_derivation();
                        a.clear_output_user_address();
                        a.clear_output_proprietary();
                    });
                }
                // rcv opens each action's value commitment: with it the seller
                // could solve cv_net for the funding note's value and change.
                // After proving it is only needed folded into bsk, so drop it
                // from every action.
                r.redact_actions(|mut a| a.clear_rcv());
            })
            .finish();
        let bytes = pczt_bytes(p)?;
        let mut rcv_left = 0;
        Verifier::new(parse_pczt(&bytes)?)
            .with_ironwood::<Infallible, _>(|bundle| {
                rcv_left = bundle.actions().iter().filter(|a| a.rcv().is_some()).count();
                Ok(())
            })
            .map_err(|e| anyhow!("verify: {e:?}"))?;
        if rcv_left > 0 {
            bail!("redaction self-check failed: {rcv_left} action(s) still carry rcv");
        }

        // Self-check: none of these may survive redaction.
        let secrets: [(&str, Vec<u8>); 5] = [
            ("payer viewing key", payer.fvk.to_bytes().to_vec()),
            ("receive viewing key", receive.fvk.to_bytes().to_vec()),
            ("item destination", carrier_to.to_raw_address_bytes().to_vec()),
            ("change address", change_to.to_raw_address_bytes().to_vec()),
            ("funding note rseed", fund.note().rseed().as_bytes().to_vec()),
        ];
        for (what, s) in &secrets {
            if bytes.windows(s.len()).any(|w| w == s.as_slice()) {
                bail!("redaction self-check failed: {what} is still in the PCZT");
            }
        }
        if let Ok(tx) = extract(parse_pczt(&bytes)?) {
            bail!("buyer alone could extract tx {}; refusing", tx.txid());
        }

        fs::write(out, &bytes)?;
        let terms = SaleTerms {
            v: 1,
            listing_hash: l.hash()?,
            carrier_action: ca,
            payout_action: pa,
            expiry_height: expiry,
            claim: claim.map(|c| auction::make_claim(c, &l.hash()?)).transpose()?,
        };
        fs::write(out.with_extension("terms.json"), serde_json::to_string_pretty(&terms)?)?;
        println!("buyer-signed, redacted PCZT {} (expires at height {expiry})", out.display());
        return Ok(());
    }
    bail!("could not bind carrier spend and successor after {MAX_BIND_TRIES} tries")
}

fn sale_accept(wallet: &Path, identity: &Path, listing: &Path, input: &Path, auction_log: Option<&str>, out: &Path) -> Result<()> {
    let l: Listing = serde_json::from_str(&fs::read_to_string(listing)?)?;
    let terms: SaleTerms = serde_json::from_str(&fs::read_to_string(input.with_extension("terms.json"))?)
        .context("read sale terms")?;
    if terms.listing_hash != l.hash()? {
        bail!("terms refer to a different listing");
    }
    if let Some(url) = auction_log {
        let log: tally_crypto::auction::AuctionLog = ureq::get(url).call()?.body_mut().read_json()?;
        let claim = terms.claim.as_ref().ok_or_else(|| anyhow!("auction sale requires a win claim"))?;
        auction::check_claim(&log, claim, &terms.listing_hash, l.price_zat)?;
    }
    let c = l.carrier()?;
    let payout = l.payout()?;

    let w = Wallet::open(wallet)?;
    let vault = find_vault(&w, &c)?;
    let ask = w.ask(identity, &vault)?;
    let (target, _) = w.heights()?;

    let p = parse_pczt(&fs::read(input)?)?;
    let expiry = u32::from(*p.global().expiry_height());
    if expiry != terms.expiry_height || expiry > l.valid_until || expiry <= u32::from(height(target)) {
        bail!("PCZT expiry is outside the listing window");
    }
    let nf = c.note.nullifier(&c.fvk).to_bytes();
    let mut ok = false;
    let p = Verifier::new(p)
        .with_ironwood::<Infallible, _>(|bundle| {
            let acts = bundle.actions();
            let carrier_ok = acts
                .get(terms.carrier_action)
                .map(|a| a.spend().nullifier().to_bytes() == nf)
                .unwrap_or(false);
            let paid = acts
                .get(terms.payout_action)
                .map(|a| {
                    a.output().recipient().as_ref() == Some(&payout)
                        && a.output().value().map(|v| v.inner()) == Some(l.price_zat)
                })
                .unwrap_or(false);
            // Exactly one action spends our carrier.
            let once = acts.iter().filter(|a| a.spend().nullifier().to_bytes() == nf).count() == 1;
            ok = carrier_ok && paid && once;
            Ok(())
        })
        .map_err(|e| anyhow!("verify: {e:?}"))?
        .finish();
    if !ok {
        bail!("PCZT does not spend the listed carrier in the agreed action, or does not pay the listed price to our payout address");
    }

    let mut s = Signer::new(p).map_err(|e| anyhow!("signer: {e:?}"))?;
    s.sign_ironwood(rng(), terms.carrier_action, &ask).map_err(|e| anyhow!("sign: {e:?}"))?;
    fs::write(out, pczt_bytes(s.finish())?)?;
    println!("seller-signed PCZT {}; broadcast with `zcash-devtool pczt send-without-storing`", out.display());
    Ok(())
}

/// The seller account whose viewing key is the listing's vault key.
fn find_vault(w: &Wallet, c: &Carrier) -> Result<Acct> {
    for uuid in w.db.get_account_ids()? {
        if let Some(a) = w.db.get_account(uuid)? {
            if a.ufvk().and_then(|k| k.orchard()) == Some(&c.fvk) {
                return w.account(a.name().ok_or_else(|| anyhow!("vault account has no name"))?);
            }
        }
    }
    bail!("this wallet does not hold the listed vault")
}

fn inspect_item(wallet: &Path, tx: &str, action: u32, collection_pk: &str, listing: Option<&Path>) -> Result<()> {
    let w = Wallet::open(wallet)?;
    let (target, _) = w.heights()?;
    let id = txid(tx)?;
    let n = w.note(id, action, target)?;
    let memo = w
        .memo(id, action)?
        .ok_or_else(|| anyhow!("no memo stored; run `zcash-devtool wallet enhance`"))?;
    let item = Item::decode(&memo).map_err(|e| anyhow!("{e}"))?;
    let pk = tally_crypto::codec::point_from_hex(collection_pk).map_err(|e| anyhow!("{e}"))?;
    println!("value_zat      {}", n.note().value().inner());
    println!("collection     {}", hex::encode(item.collection_id));
    println!("item_index     {}", item.item_index);
    println!("hop            {}", item.hop);
    println!("seller_sig_ok  {}", item.verify_seller(&pk).is_ok());
    if let Some(lp) = listing {
        let l: Listing = serde_json::from_str(&fs::read_to_string(lp)?)?;
        let c = l.carrier()?;
        let prev_nf = c.note.nullifier(&c.fvk).to_bytes();
        println!("rho==prev_nf   {}", n.note().rho().to_bytes() == prev_nf);
        println!("same_item      {}", c.item.collection_id == item.collection_id && c.item.item_index == item.item_index);
        println!("hop_advanced   {}", item.hop == c.item.hop + 1);
    }
    Ok(())
}

fn record(wallets: &[PathBuf], input: &Path) -> Result<()> {
    let tx = extract(parse_pczt(&fs::read(input)?)?).context("PCZT is not fully signed")?;
    for w in wallets {
        let mut wallet = Wallet::open(w)?;
        zcash_client_backend::data_api::wallet::decrypt_and_store_transaction(&network(), &mut wallet.db, &tx, None)
            .map_err(|e| anyhow!("store in {}: {e:?}", w.display()))?;
    }
    println!("recorded {} in {} wallet(s)", tx.txid(), wallets.len());
    Ok(())
}

fn try_extract(input: &Path) -> Result<()> {
    match extract(parse_pczt(&fs::read(input)?)?) {
        Ok(tx) => {
            let mut raw = vec![];
            tx.write(&mut raw)?;
            fs::write(input.with_extension("tx.hex"), hex::encode(raw))?;
            println!("EXTRACTED {}", tx.txid());
            // Everything a public observer can see, by pool.
            let p = |b: bool| if b { "PRESENT" } else { "none" };
            println!("  version          {:?}", tx.version());
            println!("  transparent      {}", p(tx.transparent_bundle().is_some()));
            println!("  sprout           {}", p(tx.sprout_bundle().is_some()));
            println!("  sapling          {}", p(tx.sapling_bundle().is_some()));
            println!("  orchard          {}", p(tx.orchard_bundle().is_some()));
            if let Some(b) = tx.ironwood_bundle() {
                println!("  ironwood actions {}", b.actions().len());
                println!("  ironwood balance {} zat (public: the fee leaving the pool)", i64::from(*b.value_balance()));
            }
        }
        Err(e) => println!("REFUSED {e}"),
    }
    Ok(())
}
