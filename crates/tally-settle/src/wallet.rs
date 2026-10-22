//! Opening zcash-devtool wallets: the SQLite wallet DB, the age-encrypted
//! mnemonic in keys.toml, and the Ironwood notes and witnesses we spend.
//!
//! Secrets stay in memory only. Nothing here prints keys, seeds or addresses.

use std::fs;
use std::io::Read;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use bip0039::{English, Mnemonic};
use orchard::keys::{FullViewingKey, Scope, SpendAuthorizingKey};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use secrecy::{ExposeSecret, SecretVec};
use serde::Deserialize;
use zcash_client_backend::data_api::{
    wallet::{input_selection::LockFilter, ConfirmationsPolicy, TargetHeight},
    InputSource, TargetValue, WalletCommitmentTrees, WalletRead,
};
use zcash_client_backend::wallet::ReceivedNote;
use zcash_client_sqlite::{util::SystemClock, AccountUuid, ReceivedNoteId, WalletDb};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::{BlockHeight, Network};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{ShieldedPool, TxId};

pub const NETWORK: Network = Network::TestNetwork;

pub type Db = WalletDb<rusqlite::Connection, Network, SystemClock, UnwrapErr<SysRng>>;

pub struct Wallet {
    pub dir: PathBuf,
    pub db: Db,
    pub account: AccountUuid,
}

pub struct Keys {
    pub fvk: FullViewingKey,
    pub ask: SpendAuthorizingKey,
}

#[derive(Deserialize)]
struct KeysToml {
    mnemonic: Option<String>,
}

impl Wallet {
    pub fn open(dir: &Path) -> Result<Self> {
        let db = WalletDb::for_path(dir.join("data.sqlite"), NETWORK, SystemClock, UnwrapErr(SysRng))
            .context("open wallet db")?;
        let account = *db
            .get_account_ids()?
            .first()
            .ok_or_else(|| anyhow!("wallet has no account"))?;
        Ok(Self { dir: dir.to_owned(), db, account })
    }

    /// Viewing key only; no identity file needed.
    pub fn fvk(&self) -> Result<FullViewingKey> {
        let ufvks = self.db.get_unified_full_viewing_keys()?;
        ufvks
            .get(&self.account)
            .and_then(|k| k.orchard().cloned())
            .ok_or_else(|| anyhow!("account has no Orchard/Ironwood viewing key"))
    }

    /// Decrypt the mnemonic with the age identity and derive account 0's keys.
    pub fn keys(&self, identity: &Path) -> Result<Keys> {
        let conf: KeysToml = toml::from_str(&fs::read_to_string(self.dir.join("keys.toml"))?)?;
        let ciphertext = conf.mnemonic.ok_or_else(|| anyhow!("wallet has no seed"))?;
        let identities = age::IdentityFile::from_file(identity.to_string_lossy().into_owned())?
            .into_identities()?;
        let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(ciphertext.as_bytes()))?;
        let mut buf = vec![];
        let res = decryptor
            .decrypt(identities.iter().map(|i| i.as_ref() as _))?
            .read_to_end(&mut buf);
        let phrase = SecretVec::new(buf);
        res?;
        let mnemonic = <Mnemonic<English>>::from_phrase(std::str::from_utf8(phrase.expose_secret())?)?;
        let seed = SecretVec::new(mnemonic.to_seed("").to_vec());
        let usk = UnifiedSpendingKey::from_seed(&NETWORK, seed.expose_secret(), zip32::AccountId::ZERO)
            .map_err(|e| anyhow!("derive spending key: {e:?}"))?;
        let sk = usk.orchard();
        let keys = Keys { fvk: FullViewingKey::from(sk), ask: SpendAuthorizingKey::from(sk) };
        if keys.fvk != self.fvk()? {
            return Err(anyhow!("identity does not match this wallet"));
        }
        Ok(keys)
    }

    /// (target height, anchor height) under the default ZIP 315 policy.
    pub fn heights(&self) -> Result<(TargetHeight, BlockHeight)> {
        self.db
            .get_target_and_anchor_heights(NonZeroU32::new(3).unwrap())?
            .ok_or_else(|| anyhow!("wallet not synced"))
    }

    /// A specific Ironwood note (e.g. a carrier) by txid and action index.
    pub fn note(&self, txid: TxId, index: u32, target: TargetHeight) -> Result<ReceivedNote<ReceivedNoteId, orchard::Note>> {
        let n = self
            .db
            .get_spendable_note(&txid, ShieldedPool::Ironwood, index, target, LockFilter::Unfiltered)?
            .ok_or_else(|| anyhow!("note not found or not spendable"))?;
        match n.note() {
            zcash_client_backend::wallet::Note::Orchard { note, .. } => {
                let note: orchard::Note = note.clone();
                Ok(n.clone().map_note(|_| note))
            }
            _ => Err(anyhow!("not an Ironwood note")),
        }
    }

    /// One Ironwood note worth at least `value`, excluding zero-value carriers.
    pub fn funding_note(&self, value: u64, target: TargetHeight) -> Result<ReceivedNote<ReceivedNoteId, orchard::Note>> {
        let notes = self.db.select_spendable_notes(
            self.account,
            TargetValue::AtLeast(Zatoshis::from_u64(value).map_err(|_| anyhow!("amount"))?),
            &[ShieldedPool::Ironwood],
            target,
            ConfirmationsPolicy::default(),
            &[],
            LockFilter::Unfiltered,
        )?;
        notes
            .ironwood()
            .iter()
            .filter(|n| n.note().value().inner() >= value)
            .max_by_key(|n| n.note().value().inner())
            .cloned()
            .ok_or_else(|| anyhow!("no single Ironwood note covers the amount"))
    }

    /// Ironwood anchor and witness for `position` at `anchor_height`.
    pub fn witness(
        &mut self,
        position: incrementalmerkletree::Position,
        anchor_height: BlockHeight,
    ) -> Result<(orchard::Anchor, orchard::tree::MerklePath)> {
        self.db
            .with_ironwood_tree_mut::<_, _, anyhow::Error>(|tree| {
                let root = tree
                    .root_at_checkpoint_id(&anchor_height)?
                    .ok_or_else(|| anyhow!("no Ironwood checkpoint at anchor height"))?;
                let path = tree
                    .witness_at_checkpoint_id_caching(position, &anchor_height)?
                    .ok_or_else(|| anyhow!("witness pruned"))?;
                Ok((root.into(), path.into()))
            })?
            .ok_or_else(|| anyhow!("wallet does not track Ironwood"))
    }
}

impl Wallet {
    /// The raw 512-byte memo of one of our received notes.
    pub fn memo(&self, txid: TxId, action: u32) -> Result<Option<[u8; 512]>> {
        let id = zcash_client_backend::wallet::NoteId::new(txid, ShieldedPool::Ironwood, action as u16);
        Ok(self
            .db
            .get_memo(id)?
            .map(|m| *zcash_protocol::memo::MemoBytes::from(&m).as_array()))
    }
}

/// A fresh receiving address for this account: a random diversifier, so no
/// address is reused. (Diversified addresses share an IVK; see THREAT_MODEL.)
pub fn fresh_address(fvk: &FullViewingKey, scope: Scope) -> orchard::Address {
    let mut d = [0u8; 11];
    rand_core_06::RngCore::fill_bytes(&mut rand_core_06::OsRng, &mut d);
    fvk.address_at(zip32::DiversifierIndex::from(d), scope)
}
