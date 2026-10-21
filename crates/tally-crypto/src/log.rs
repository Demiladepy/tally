//! Bulletin log hash chain: entry_i = H(entry_{i-1} ‖ H(ballot_i)), starting
//! from a genesis value bound to the auction. The final entry is the log
//! root pinned at close.

use crate::hash::Transcript;

pub fn genesis(auction_id: &[u8; 32]) -> [u8; 32] {
    let mut t = Transcript::new("log-genesis");
    t.append("auction_id", auction_id);
    t.digest32()
}

pub fn entry_hash(prev: &[u8; 32], ballot_hash: &[u8; 32]) -> [u8; 32] {
    let mut t = Transcript::new("log-entry");
    t.append("prev", prev);
    t.append("ballot", ballot_hash);
    t.digest32()
}

pub fn root<'a>(auction_id: &[u8; 32], ballot_hashes: impl IntoIterator<Item = &'a [u8; 32]>) -> [u8; 32] {
    ballot_hashes
        .into_iter()
        .fold(genesis(auction_id), |prev, h| entry_hash(&prev, h))
}
