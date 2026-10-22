//! Opening zcash-devtool wallets: the SQLite wallet DB, the age-encrypted
//! mnemonic in keys.toml, and the Ironwood notes and witnesses we spend.
//!
//! A wallet holds several ZIP 32 accounts made with
//! `zcash-devtool wallet generate-account`. Tally keeps each item in its own
//! "vault" account and pays each sale into its own payout account, so a
//! viewing key shared with a counterparty never reveals anything else.
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
    Account, InputSource, TargetValue, WalletCommitmentTrees, WalletRead,
};
use zcash_client_backend::wallet::{NoteId, ReceivedNote};
use zcash_client_sqlite::{util::SystemClock, AccountUuid, ReceivedNoteId, WalletDb};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::{BlockHeight, Network};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{ShieldedPool, TxId};

pub const NETWORK: Network = Network::TestNetwork;

pub type Db = WalletDb<rusqlite::Connection, Network, SystemClock, UnwrapErr<SysRng>>;
pub type Received = ReceivedNote<ReceivedNoteId, orchard::Note>;

pub struct Wallet {
    pub dir: PathBuf,
    pub db: Db,
}

/// One account of a wallet, chosen by the name given at `generate-account`.
#[derive(Clone)]
pub struct Acct {
    pub uuid: AccountUuid,
    pub index: zip32::AccountId,
    pub fvk: FullViewingKey,
}

#[derive(Deserialize)]
struct KeysToml {
    mnemonic: Option<String>,
}

impl Wallet {
    pub fn open(dir: &Path) -> Result<Self> {
        let db = WalletDb::for_path(dir.join("data.sqlite"), NETWORK, SystemClock, UnwrapErr(SysRng))
            .context("open wallet db")?;
        Ok(Self { dir: dir.to_owned(), db })
    }

    pub fn account(&self, name: &str) -> Result<Acct> {
        for uuid in self.db.get_account_ids()? {
            let a = self.db.get_account(uuid)?.ok_or_else(|| anyhow!("account vanished"))?;
            if a.name() != Some(name) {
                continue;
            }
            let index = a
                .source()
                .key_derivation()
                .map(|d| d.account_index())
                .ok_or_else(|| anyhow!("account '{name}' is not derived from this wallet's seed"))?;
            let fvk = a
                .ufvk()
                .and_then(|k| k.orchard().cloned())
                .ok_or_else(|| anyhow!("account '{name}' has no Orchard/Ironwood key"))?;
            return Ok(Acct { uuid, index, fvk });
        }
        Err(anyhow!("no account named '{name}' (create it with `zcash-devtool wallet generate-account`)"))
    }

    /// Decrypt the mnemonic with the age identity and derive `acct`'s
    /// spend authorizing key.
    pub fn ask(&self, identity: &Path, acct: &Acct) -> Result<SpendAuthorizingKey> {
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
        let usk = UnifiedSpendingKey::from_seed(&NETWORK, seed.expose_secret(), acct.index)
            .map_err(|e| anyhow!("derive spending key: {e:?}"))?;
        let sk = usk.orchard();
        if FullViewingKey::from(sk) != acct.fvk {
            return Err(anyhow!("identity does not match this account"));
        }
        Ok(SpendAuthorizingKey::from(sk))
    }

    /// (target height, anchor height) with 3 confirmations.
    pub fn heights(&self) -> Result<(TargetHeight, BlockHeight)> {
        self.db
            .get_target_and_anchor_heights(NonZeroU32::new(3).unwrap())?
            .ok_or_else(|| anyhow!("wallet not synced"))
    }

    /// A specific Ironwood note (e.g. a carrier) by txid and action index.
    pub fn note(&self, txid: TxId, index: u32, target: TargetHeight) -> Result<Received> {
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

    /// One Ironwood note in `acct` worth at least `value`.
    pub fn funding_note(&self, acct: &Acct, value: u64, target: TargetHeight) -> Result<Received> {
        let notes = self.db.select_spendable_notes(
            acct.uuid,
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
                    .ok_or_else(|| anyhow!("no Ironwood checkpoint at height {anchor_height}; sync and retry"))?;
                let path = tree
                    .witness_at_checkpoint_id_caching(position, &anchor_height)?
                    .ok_or_else(|| anyhow!("witness pruned"))?;
                Ok((root.into(), path.into()))
            })?
            .ok_or_else(|| anyhow!("wallet does not track Ironwood"))
    }

    /// The raw 512-byte memo of one of our received notes (run
    /// `zcash-devtool wallet enhance` first: compact blocks carry no memos).
    pub fn memo(&self, txid: TxId, action: u32) -> Result<Option<[u8; 512]>> {
        let id = NoteId::new(txid, ShieldedPool::Ironwood, action as u16);
        Ok(self.db.get_memo(id)?.map(|m| *MemoBytes::from(&m).as_array()))
    }
}

/// A fresh receiving address for `fvk`, at a random diversifier.
pub fn fresh_address(fvk: &FullViewingKey, scope: Scope) -> orchard::Address {
    let mut d = [0u8; 11];
    rand_core_06::RngCore::fill_bytes(&mut rand_core_06::OsRng, &mut d);
    fvk.address_at(zip32::DiversifierIndex::from(d), scope)
}
