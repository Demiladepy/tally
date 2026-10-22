//! The listing a seller hands a buyer, and the terms a buyer hands back.
//!
//! A listing carries exactly what the buyer needs to build the sale without
//! touching the seller's wallet: the carrier note's parts and witness, the
//! viewing key of the item's own vault account (it can see nothing but this
//! item), the payout address of a fresh payout account, and the price.
//! It is sent privately to the buyer, never published.

use anyhow::{anyhow, bail, Result};
use incrementalmerkletree::Hashable;
use orchard::keys::FullViewingKey;
use orchard::note::{ExtractedNoteCommitment, RandomSeed, Rho};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use serde::{Deserialize, Serialize};
use tally_zcash::memo::Item;

#[derive(Serialize, Deserialize)]
pub struct Listing {
    pub v: u8,
    /// Mint (or previous sale) txid and action holding the carrier.
    pub carrier_txid: String,
    pub carrier_action: u32,
    pub vault_fvk: String,
    pub note_recipient: String,
    pub note_rho: String,
    pub note_rseed: String,
    pub merkle_position: u32,
    pub merkle_path: Vec<String>,
    pub anchor_height: u32,
    pub anchor: String,
    pub item_memo: String,
    pub collection_pk: String,
    pub price_zat: u64,
    pub payout: String,
    /// Height after which the seller will not sign.
    pub valid_until: u32,
}

/// What the buyer commits to alongside the redacted PCZT.
#[derive(Serialize, Deserialize)]
pub struct SaleTerms {
    pub v: u8,
    pub listing_hash: String,
    pub carrier_action: usize,
    pub payout_action: usize,
    pub expiry_height: u32,
}

pub struct Carrier {
    pub fvk: FullViewingKey,
    pub note: orchard::Note,
    pub path: MerklePath,
    pub anchor: orchard::Anchor,
    pub item: Item,
}

fn arr<const N: usize>(h: &str) -> Result<[u8; N]> {
    hex::decode(h)?.try_into().map_err(|_| anyhow!("wrong length"))
}

impl Listing {
    pub fn new_from(c: &Carrier, rest: ListingRest) -> Result<Self> {
        Ok(Self {
            v: 1,
            carrier_txid: rest.carrier_txid,
            carrier_action: rest.carrier_action,
            vault_fvk: hex::encode(c.fvk.to_bytes()),
            note_recipient: hex::encode(c.note.recipient().to_raw_address_bytes()),
            note_rho: hex::encode(c.note.rho().to_bytes()),
            note_rseed: hex::encode(c.note.rseed().as_bytes()),
            merkle_position: c.path.position(),
            merkle_path: c.path.auth_path().iter().map(|h| hex::encode(h.to_bytes())).collect(),
            anchor_height: rest.anchor_height,
            anchor: hex::encode(c.anchor.to_bytes()),
            item_memo: hex::encode(c.item.encode().map_err(|e| anyhow!("{e}"))?),
            collection_pk: rest.collection_pk,
            price_zat: rest.price_zat,
            payout: hex::encode(rest.payout.to_raw_address_bytes()),
            valid_until: rest.valid_until,
        })
    }

    pub fn hash(&self) -> Result<String> {
        let mut t = tally_crypto::hash::Transcript::new("listing");
        t.append("json", serde_json::to_string(self)?.as_bytes());
        Ok(hex::encode(t.digest32()))
    }

    pub fn payout(&self) -> Result<orchard::Address> {
        Option::from(orchard::Address::from_raw_address_bytes(&arr(&self.payout)?))
            .ok_or_else(|| anyhow!("bad payout address"))
    }

    /// Parse and check everything the buyer can check on its own:
    /// the note opens to a zero-value carrier the vault key controls, its
    /// commitment is in the tree at the stated anchor, and the memo is a
    /// Tally item signed by the stated collection key.
    pub fn carrier(&self) -> Result<Carrier> {
        if self.v != 1 {
            bail!("unsupported listing version");
        }
        let fvk = FullViewingKey::from_bytes(&arr(&self.vault_fvk)?).ok_or_else(|| anyhow!("bad vault key"))?;
        let recipient = Option::from(orchard::Address::from_raw_address_bytes(&arr(&self.note_recipient)?))
            .ok_or_else(|| anyhow!("bad note recipient"))?;
        if fvk.scope_for_address(&recipient).is_none() {
            bail!("carrier note is not controlled by the stated vault key");
        }
        let rho = Option::<Rho>::from(Rho::from_bytes(&arr(&self.note_rho)?)).ok_or_else(|| anyhow!("bad rho"))?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(arr(&self.note_rseed)?, &rho))
            .ok_or_else(|| anyhow!("bad rseed"))?;
        let note = Option::<orchard::Note>::from(orchard::Note::from_parts(
            recipient,
            NoteValue::from_raw(0),
            rho,
            rseed,
            orchard::note::NoteVersion::V3,
        ))
        .ok_or_else(|| anyhow!("note parts do not form a note"))?;

        if self.merkle_path.len() != 32 {
            bail!("bad merkle path");
        }
        let mut auth = [MerkleHashOrchard::empty_leaf(); 32];
        for (slot, h) in auth.iter_mut().zip(&self.merkle_path) {
            *slot = Option::from(MerkleHashOrchard::from_bytes(&arr(h)?)).ok_or_else(|| anyhow!("bad merkle node"))?;
        }
        let path = MerklePath::from_parts(self.merkle_position, auth);
        let anchor = Option::<orchard::Anchor>::from(orchard::Anchor::from_bytes(arr(&self.anchor)?))
            .ok_or_else(|| anyhow!("bad anchor"))?;
        if path.root(ExtractedNoteCommitment::from(note.commitment())) != anchor {
            bail!("carrier note is not in the note commitment tree at the stated anchor");
        }

        let mut memo = [0u8; 512];
        memo.copy_from_slice(&hex::decode(&self.item_memo)?);
        let item = Item::decode(&memo).map_err(|e| anyhow!("{e}"))?;
        let pk = tally_crypto::codec::point_from_hex(&self.collection_pk).map_err(|e| anyhow!("{e}"))?;
        item.verify_seller(&pk).map_err(|e| anyhow!("{e}"))?;
        Ok(Carrier { fvk, note, path, anchor, item })
    }
}

pub struct ListingRest {
    pub carrier_txid: String,
    pub carrier_action: u32,
    pub anchor_height: u32,
    pub collection_pk: String,
    pub price_zat: u64,
    pub payout: orchard::Address,
    pub valid_until: u32,
}
