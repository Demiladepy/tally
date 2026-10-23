//! 512-byte memo layouts (ZIP 302 "arbitrary data": first byte 0xF5).
//!
//! Item (carrier note):
//!   F5 | "TLY1" | collection_id[32] | item_index u32 | hop u32 |
//!   art_len u16 | art[art_len] | seller_sig[64] | zero padding
//!
//! The seller signature covers (collection_id, item_index, art) and stays
//! the same across hops, so it proves the seller minted this content, not
//! that a given note is genuine. Genuineness comes from the lineage check
//! (each hop's rho = previous nullifier), as in Zarrier.
//!
//! Bond:
//!   F5 | "TLYB" | auction_id[32] | ballot_hash[32] | ua_len u16 | refund_ua | zero padding

use rand_core::{CryptoRng, RngCore};
use tally_crypto::schnorr::{self, Signature};
use tally_crypto::{Point, Scalar};
use tally_crypto::codec::{point_from_hex, point_to_hex, scalar_from_hex, scalar_to_hex};
use thiserror::Error;

pub const MEMO_LEN: usize = 512;
const ARBITRARY: u8 = 0xF5;
const ITEM_TAG: &[u8; 4] = b"TLY1";
const BOND_TAG: &[u8; 4] = b"TLYB";
const ITEM_HEADER: usize = 1 + 4 + 32 + 4 + 4 + 2;
const SIG_LEN: usize = 64;
pub const MAX_ART: usize = MEMO_LEN - ITEM_HEADER - SIG_LEN;
const MINT_PURPOSE: &str = "item-mint";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MemoError {
    #[error("not a Tally memo")]
    WrongTag,
    #[error("memo field too long")]
    TooLong,
    #[error("malformed memo")]
    Malformed,
    #[error("seller signature invalid")]
    BadSignature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub collection_id: [u8; 32],
    pub item_index: u32,
    pub hop: u32,
    pub art: Vec<u8>,
    pub seller_sig: Signature,
}

fn mint_message(collection_id: &[u8; 32], item_index: u32, art: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(36 + art.len());
    m.extend_from_slice(collection_id);
    m.extend_from_slice(&item_index.to_le_bytes());
    m.extend_from_slice(art);
    m
}

fn sig_bytes(sig: &Signature) -> Vec<u8> {
    let mut out = hex::decode(point_to_hex(&sig.r)).unwrap();
    out.extend(hex::decode(scalar_to_hex(&sig.s)).unwrap());
    out
}

fn sig_from_bytes(b: &[u8]) -> Result<Signature, MemoError> {
    let r = point_from_hex(&hex::encode(&b[..32])).map_err(|_| MemoError::Malformed)?;
    let s = scalar_from_hex(&hex::encode(&b[32..64])).map_err(|_| MemoError::Malformed)?;
    Ok(Signature { r, s })
}

impl Item {
    /// Mint item content signed by the seller's collection key.
    pub fn mint<R: RngCore + CryptoRng>(
        seller_sk: &Scalar,
        collection_id: [u8; 32],
        item_index: u32,
        art: Vec<u8>,
        rng: &mut R,
    ) -> Result<Self, MemoError> {
        if art.len() > MAX_ART {
            return Err(MemoError::TooLong);
        }
        let seller_sig = schnorr::sign(MINT_PURPOSE, seller_sk, &mint_message(&collection_id, item_index, &art), rng);
        Ok(Self { collection_id, item_index, hop: 0, art, seller_sig })
    }

    pub fn verify_seller(&self, seller_pk: &Point) -> Result<(), MemoError> {
        let msg = mint_message(&self.collection_id, self.item_index, &self.art);
        if schnorr::verify(MINT_PURPOSE, seller_pk, &msg, &self.seller_sig) {
            Ok(())
        } else {
            Err(MemoError::BadSignature)
        }
    }

    /// The same item, one transfer later.
    pub fn next_hop(&self) -> Self {
        Self { hop: self.hop + 1, ..self.clone() }
    }

    pub fn encode(&self) -> Result<[u8; MEMO_LEN], MemoError> {
        if self.art.len() > MAX_ART {
            return Err(MemoError::TooLong);
        }
        let mut m = [0u8; MEMO_LEN];
        let mut w = Writer { buf: &mut m, pos: 0 };
        w.put(&[ARBITRARY]);
        w.put(ITEM_TAG);
        w.put(&self.collection_id);
        w.put(&self.item_index.to_le_bytes());
        w.put(&self.hop.to_le_bytes());
        w.put(&(self.art.len() as u16).to_le_bytes());
        w.put(&self.art);
        w.put(&sig_bytes(&self.seller_sig));
        Ok(m)
    }

    pub fn decode(m: &[u8; MEMO_LEN]) -> Result<Self, MemoError> {
        let mut r = Reader { buf: m, pos: 0 };
        if r.take(1)? != [ARBITRARY] || r.take(4)? != ITEM_TAG {
            return Err(MemoError::WrongTag);
        }
        let collection_id = r.array32()?;
        let item_index = r.u32()?;
        let hop = r.u32()?;
        let art_len = r.u16()? as usize;
        if art_len > MAX_ART {
            return Err(MemoError::Malformed);
        }
        let art = r.take(art_len)?.to_vec();
        let seller_sig = sig_from_bytes(r.take(SIG_LEN)?)?;
        r.zero_tail()?;
        Ok(Self { collection_id, item_index, hop, art, seller_sig })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bond {
    pub auction_id: [u8; 32],
    pub ballot_hash: [u8; 32],
    /// One-time unified address for the refund. Never reused.
    pub refund_ua: String,
}

/// Text tag for bond memos. Text (not ZIP 302 binary) because most wallets
/// only send UTF-8 memos, and a user can paste this one by hand.
const BOND_TEXT_TAG: &str = "TLYB1";

impl Bond {
    /// `TLYB1 <auction_id hex> <ballot_hash hex> <refund_ua>`: plain ASCII.
    pub fn text(&self) -> String {
        format!("{BOND_TEXT_TAG} {} {} {}", hex::encode(self.auction_id), hex::encode(self.ballot_hash), self.refund_ua)
    }

    /// The memo as wallets send it: the text, zero-padded to 512 bytes.
    pub fn encode(&self) -> Result<[u8; MEMO_LEN], MemoError> {
        let t = self.text();
        if t.len() > MEMO_LEN || !self.refund_ua.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(MemoError::TooLong);
        }
        let mut m = [0u8; MEMO_LEN];
        m[..t.len()].copy_from_slice(t.as_bytes());
        Ok(m)
    }

    /// Accepts the text form (tolerating surrounding whitespace a wallet may
    /// add) and the earlier binary form, so old bonds stay readable.
    pub fn decode(m: &[u8; MEMO_LEN]) -> Result<Self, MemoError> {
        if m[0] == ARBITRARY {
            return Self::decode_binary(m);
        }
        let end = m.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
        let s = std::str::from_utf8(&m[..end]).map_err(|_| MemoError::Malformed)?.trim();
        let parts: Vec<&str> = s.split_whitespace().collect();
        let [tag, id, hash, ua] = parts.as_slice() else {
            return Err(MemoError::WrongTag);
        };
        if *tag != BOND_TEXT_TAG {
            return Err(MemoError::WrongTag);
        }
        let h32 = |h: &str| -> Result<[u8; 32], MemoError> {
            hex::decode(h).ok().and_then(|v| v.try_into().ok()).ok_or(MemoError::Malformed)
        };
        Ok(Self { auction_id: h32(id)?, ballot_hash: h32(hash)?, refund_ua: ua.to_string() })
    }

    /// Binary form used by the first testnet auction (F5 | "TLYB" | ...).
    pub fn encode_binary(&self) -> Result<[u8; MEMO_LEN], MemoError> {
        let ua = self.refund_ua.as_bytes();
        if 1 + 4 + 64 + 2 + ua.len() > MEMO_LEN {
            return Err(MemoError::TooLong);
        }
        let mut m = [0u8; MEMO_LEN];
        let mut w = Writer { buf: &mut m, pos: 0 };
        w.put(&[ARBITRARY]);
        w.put(BOND_TAG);
        w.put(&self.auction_id);
        w.put(&self.ballot_hash);
        w.put(&(ua.len() as u16).to_le_bytes());
        w.put(ua);
        Ok(m)
    }

    fn decode_binary(m: &[u8; MEMO_LEN]) -> Result<Self, MemoError> {
        let mut r = Reader { buf: m, pos: 0 };
        if r.take(1)? != [ARBITRARY] || r.take(4)? != BOND_TAG {
            return Err(MemoError::WrongTag);
        }
        let auction_id = r.array32()?;
        let ballot_hash = r.array32()?;
        let len = r.u16()? as usize;
        let refund_ua = String::from_utf8(r.take(len)?.to_vec()).map_err(|_| MemoError::Malformed)?;
        r.zero_tail()?;
        Ok(Self { auction_id, ballot_hash, refund_ua })
    }
}

struct Writer<'a> {
    buf: &'a mut [u8; MEMO_LEN],
    pos: usize,
}

impl Writer<'_> {
    fn put(&mut self, b: &[u8]) {
        self.buf[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
    }
}

struct Reader<'a> {
    buf: &'a [u8; MEMO_LEN],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], MemoError> {
        let end = self.pos.checked_add(n).filter(|&e| e <= MEMO_LEN).ok_or(MemoError::Malformed)?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn array32(&mut self) -> Result<[u8; 32], MemoError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn u32(&mut self) -> Result<u32, MemoError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u16(&mut self) -> Result<u16, MemoError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    /// Reject trailing data so one item has exactly one encoding.
    fn zero_tail(&self) -> Result<(), MemoError> {
        if self.buf[self.pos..].iter().all(|&b| b == 0) {
            Ok(())
        } else {
            Err(MemoError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use tally_crypto::{g, random_scalar};

    #[test]
    fn item_roundtrip_with_zarrier_sized_art() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let sk = random_scalar(&mut rng);
        let item = Item::mint(&sk, [9; 32], 3, vec![0xAB; 386], &mut rng).unwrap();
        let back = Item::decode(&item.encode().unwrap()).unwrap();
        assert_eq!(back, item);
        back.verify_seller(&(g() * sk)).unwrap();
        // The signature survives a transfer: it attests content, not the note.
        back.next_hop().verify_seller(&(g() * sk)).unwrap();
        assert_eq!(MAX_ART, 401);
    }

    #[test]
    fn item_rejects_oversize_tamper_and_trailing_bytes() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let sk = random_scalar(&mut rng);
        assert_eq!(Item::mint(&sk, [0; 32], 0, vec![0; MAX_ART + 1], &mut rng), Err(MemoError::TooLong));

        let item = Item::mint(&sk, [0; 32], 1, vec![1, 2, 3], &mut rng).unwrap();
        let mut forged = item.clone();
        forged.item_index = 2;
        assert_eq!(forged.verify_seller(&(g() * sk)), Err(MemoError::BadSignature));

        let mut m = item.encode().unwrap();
        m[MEMO_LEN - 1] = 1;
        assert_eq!(Item::decode(&m), Err(MemoError::Malformed));
        m = item.encode().unwrap();
        m[1] = b'X';
        assert_eq!(Item::decode(&m), Err(MemoError::WrongTag));
    }

    #[test]
    fn bond_text_memo_is_plain_ascii_and_tolerates_whitespace() {
        let bond = Bond { auction_id: [0xab; 32], ballot_hash: [0x01; 32], refund_ua: "utest1abc".into() };
        let m = bond.encode().unwrap();
        assert!(m[0] < 0xF5, "ZIP 302 text memo");
        assert!(std::str::from_utf8(&m[..bond.text().len()]).is_ok());
        assert_eq!(Bond::decode(&m).unwrap(), bond);
        // A wallet that adds a trailing newline or spaces still decodes.
        let t = format!("  {}\n", bond.text());
        let mut m2 = [0u8; MEMO_LEN];
        m2[..t.len()].copy_from_slice(t.as_bytes());
        assert_eq!(Bond::decode(&m2).unwrap(), bond);
        // The earlier binary form still decodes.
        assert_eq!(Bond::decode(&bond.encode_binary().unwrap()).unwrap(), bond);
        // Garbage and wrong tags don't.
        let mut bad = m;
        bad[0] = b'X';
        assert!(Bond::decode(&bad).is_err());
    }

    #[test]
    fn bond_roundtrip() {
        let bond = Bond {
            auction_id: [1; 32],
            ballot_hash: [2; 32],
            refund_ua: "utest1".to_string() + &"q".repeat(200),
        };
        assert_eq!(Bond::decode(&bond.encode().unwrap()).unwrap(), bond);
        let too_long = Bond { refund_ua: "x".repeat(500), ..bond };
        assert_eq!(too_long.encode(), Err(MemoError::TooLong));
    }
}
