//! tally-committee: the committee's side of a Tally auction.
//!
//! DKG (each member runs these; only `dealing-J.json` and `committee.json`
//! are public, and dealings carry each share encrypted to its recipient):
//!   tally-committee keygen --identity m1.age                (prints the member's age recipient)
//!   tally-committee deal   --j 1 --n 3 --t 2 --recipients age1..,age1..,age1.. --out dealing-1.json
//!   tally-committee finish --j 1 --identity m1.age --dealings dealing-1.json,dealing-2.json,dealing-3.json
//!                          --names A,B,C --secret m1.secret --public committee.json
//! After close:
//!   tally-committee attest --j 1 --secret m1.secret --log URL --bonds bonds.json --out sig-1.json
//!   tally-committee post-bonds --log URL --bonds bonds.json --sigs sig-1.json,sig-3.json
//!   tally-committee share  --j 1 --secret m1.secret --log URL --target T_8          (one share)
//!   tally-committee clear  --log URL --member 1:m1.secret --member 3:m3.secret --block-hash HEX
//!   tally-committee verify --log URL
//!
//! `clear` runs the adaptive binary search for members whose secrets are on
//! this machine. In a distributed committee each member runs `share` per
//! target instead and anyone combines with `combine`.
//!
//! Secrets are only ever written to the paths the member names. This tool
//! prints no secret, no ballot content and no bid.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use rand_core::OsRng;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use tally_crypto::auction::{self, AuctionLog, BondAttestation, MemberSig};
use tally_crypto::codec;
use tally_crypto::dkg::{self, CommitteeKey};
use tally_crypto::manifest::Committee;
use tally_crypto::threshold::{self, DecryptionShare};
use tally_crypto::{Point, Scalar};

#[derive(Parser)]
#[command(about = "Tally committee: DKG, bond attestation, threshold decryption, clearing")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create this member's transport identity (age). Prints the public recipient.
    Keygen {
        #[arg(long)]
        identity: PathBuf,
    },
    /// Deal a degree t-1 polynomial; shares are age-encrypted to each member.
    Deal {
        #[arg(long)]
        j: u32,
        #[arg(long)]
        n: u32,
        #[arg(long)]
        t: u32,
        #[arg(long, value_delimiter = ',')]
        recipients: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify every dealing, derive this member's key share and the public key.
    Finish {
        #[arg(long)]
        j: u32,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long, value_delimiter = ',')]
        dealings: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        names: Vec<String>,
        #[arg(long)]
        secret: PathBuf,
        #[arg(long)]
        public: PathBuf,
    },
    /// Sign the bonded set (entries whose ballot hash has a sufficient bond).
    Attest {
        #[arg(long)]
        j: u32,
        #[arg(long)]
        secret: PathBuf,
        #[arg(long)]
        log: String,
        #[arg(long)]
        bonds: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Combine member signatures into an attestation and post it.
    PostBonds {
        #[arg(long)]
        log: String,
        #[arg(long)]
        bonds: PathBuf,
        #[arg(long, value_delimiter = ',')]
        sigs: Vec<PathBuf>,
    },
    /// One decryption share for one target the clearing currently needs.
    Share {
        #[arg(long)]
        j: u32,
        #[arg(long)]
        secret: PathBuf,
        #[arg(long)]
        log: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Combine share files for one target and post the decryption record.
    Combine {
        #[arg(long)]
        log: String,
        #[arg(long)]
        target: String,
        #[arg(long, value_delimiter = ',')]
        shares: Vec<PathBuf>,
    },
    /// Run clearing with local members' secrets, then post the result.
    Clear {
        #[arg(long)]
        log: String,
        /// `j:path/to/secret`, repeat for at least t members.
        #[arg(long = "member")]
        members: Vec<String>,
        /// Block hash at the close height (display order, as explorers show it).
        #[arg(long)]
        block_hash: String,
    },
    /// Run every public check on an auction log (URL or file).
    Verify {
        #[arg(long)]
        log: String,
    },
}

/// Public part of a dealing. `shares[k]` is the share for member k+1,
/// age-encrypted (armored) to that member's recipient.
#[derive(Serialize, Deserialize)]
struct DealingFile {
    dealer: u32,
    n: u32,
    t: u32,
    #[serde(with = "codec::points")]
    commitments: Vec<Point>,
    shares: Vec<String>,
}

/// What `tally-settle scan-bonds` writes from the escrow account.
#[derive(Deserialize)]
struct BondsFile {
    auction_id: String,
    bonds: Vec<BondSeen>,
}

#[derive(Deserialize)]
struct BondSeen {
    ballot_hash: String,
    value_zat: u64,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { identity } => keygen(&identity),
        Cmd::Deal { j, n, t, recipients, out } => deal(j, n, t, &recipients, &out),
        Cmd::Finish { j, identity, dealings, names, secret, public } => finish(j, &identity, &dealings, &names, &secret, &public),
        Cmd::Attest { j, secret, log, bonds, out } => attest(j, &secret, &log, &bonds, &out),
        Cmd::PostBonds { log, bonds, sigs } => post_bonds(&log, &bonds, &sigs),
        Cmd::Share { j, secret, log, target, out } => share(j, &secret, &log, &target, &out),
        Cmd::Combine { log, target, shares } => combine(&log, &target, &shares),
        Cmd::Clear { log, members, block_hash } => clear(&log, &members, &block_hash),
        Cmd::Verify { log } => verify(&log),
    }
}

fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("{} already exists; refusing to overwrite", path.display()))?;
    f.write_all(data)?;
    Ok(())
}

fn keygen(identity: &Path) -> Result<()> {
    let id = age::x25519::Identity::generate();
    write_new(identity, format!("{}\n", id.to_string().expose_secret()).as_bytes())?;
    println!("{}", id.to_public());
    Ok(())
}

fn encrypt_to(recipient: &str, plaintext: &[u8]) -> Result<String> {
    let r = age::x25519::Recipient::from_str(recipient).map_err(|e| anyhow!("bad recipient: {e}"))?;
    let enc = age::Encryptor::with_recipients(std::iter::once(&r as &dyn age::Recipient))?;
    let mut out = vec![];
    let mut w = enc.wrap_output(age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor)?)?;
    w.write_all(plaintext)?;
    w.finish().and_then(|a| a.finish())?;
    Ok(String::from_utf8(out)?)
}

fn decrypt_with(identity: &Path, armored: &str) -> Result<Vec<u8>> {
    let ids = age::IdentityFile::from_file(identity.to_string_lossy().into_owned())?.into_identities()?;
    let d = age::Decryptor::new(age::armor::ArmoredReader::new(armored.as_bytes()))?;
    let mut buf = vec![];
    d.decrypt(ids.iter().map(|i| i.as_ref() as _))?.read_to_end(&mut buf)?;
    Ok(buf)
}

fn deal(j: u32, n: u32, t: u32, recipients: &[String], out: &Path) -> Result<()> {
    if recipients.len() != n as usize {
        bail!("need exactly n recipients, in member order");
    }
    let d = dkg::deal(j, n, t, &mut OsRng).map_err(|e| anyhow!("{e}"))?;
    let shares = d
        .shares
        .iter()
        .zip(recipients)
        .map(|(s, r)| encrypt_to(r, codec::scalar_to_hex(s).as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    let file = DealingFile { dealer: j, n, t, commitments: d.commitments, shares };
    write_new(out, serde_json::to_string_pretty(&file)?.as_bytes())?;
    println!("dealing {} written ({} encrypted shares)", out.display(), n);
    Ok(())
}

fn finish(j: u32, identity: &Path, dealings: &[PathBuf], names: &[String], secret: &Path, public: &Path) -> Result<()> {
    let files: Vec<DealingFile> = dealings
        .iter()
        .map(|p| Ok(serde_json::from_str(&fs::read_to_string(p)?)?))
        .collect::<Result<_>>()?;
    let (n, t) = (files[0].n, files[0].t);
    if files.len() != n as usize || files.iter().any(|f| f.n != n || f.t != t) || names.len() != n as usize {
        bail!("need n dealings with matching (n, t) and n member names");
    }
    let mut dealers: Vec<u32> = files.iter().map(|f| f.dealer).collect();
    dealers.sort();
    if dealers != (1..=n).collect::<Vec<_>>() {
        bail!("need exactly one dealing from each member 1..=n");
    }
    let mut received = vec![];
    for f in &files {
        let ct = f.shares.get(j as usize - 1).ok_or_else(|| anyhow!("dealing has no share for us"))?;
        let s = codec::scalar_from_hex(std::str::from_utf8(&decrypt_with(identity, ct)?)?).map_err(|e| anyhow!("{e}"))?;
        received.push((f.dealer, f.commitments.clone(), s));
    }
    let refs: Vec<(u32, &[Point], Scalar)> = received.iter().map(|(d, c, s)| (*d, c.as_slice(), *s)).collect();
    let x_j = dkg::member_secret(j, &refs).map_err(|e| anyhow!("{e} (complain publicly about this dealer)"))?;
    let key = dkg::committee_key(n, t, &files.iter().map(|f| f.commitments.clone()).collect::<Vec<_>>()).map_err(|e| anyhow!("{e}"))?;
    if key.x[j as usize - 1] != tally_crypto::g() * x_j {
        bail!("derived share does not match the public verification key");
    }
    write_new(secret, codec::scalar_to_hex(&x_j).as_bytes())?;
    let committee = Committee { key, members: names.to_vec() };
    fs::write(public, serde_json::to_string_pretty(&committee)?)?;
    println!("member {j}: key share verified against every dealing; public key in {}", public.display());
    Ok(())
}

fn read_secret(j: u32, path: &Path, key: &CommitteeKey) -> Result<Scalar> {
    let x = codec::scalar_from_hex(fs::read_to_string(path)?.trim()).map_err(|e| anyhow!("{e}"))?;
    if key.x.get(j as usize - 1) != Some(&(tally_crypto::g() * x)) {
        bail!("secret for member {j} does not match this auction's committee");
    }
    Ok(x)
}

fn fetch_log(log: &str) -> Result<AuctionLog> {
    if log.starts_with("http://") || log.starts_with("https://") {
        Ok(ureq::get(log).call()?.body_mut().read_json()?)
    } else {
        Ok(serde_json::from_str(&fs::read_to_string(log)?)?)
    }
}

fn post<T: Serialize>(log: &str, path: &str, v: &T) -> Result<()> {
    let url = format!("{log}/{path}");
    match ureq::post(&url).send_json(v) {
        Ok(_) => Ok(()),
        Err(ureq::Error::StatusCode(c)) => bail!("bulletin refused {path}: HTTP {c}"),
        Err(e) => Err(e.into()),
    }
}

/// Map attested bonds to log entries: an entry is bonded if a bond of at
/// least `bond_zat` carries its ballot hash. Unknown hashes are ignored.
fn bonded_indices(log: &AuctionLog, bonds: &Path) -> Result<Vec<u64>> {
    let b: BondsFile = serde_json::from_str(&fs::read_to_string(bonds)?)?;
    if b.auction_id != hex::encode(log.manifest.auction_id) {
        bail!("bonds file is for a different auction");
    }
    let mut paid: BTreeMap<String, u64> = BTreeMap::new();
    for x in &b.bonds {
        *paid.entry(x.ballot_hash.clone()).or_default() += x.value_zat;
    }
    Ok(log
        .entries
        .iter()
        .filter(|e| paid.get(&hex::encode(e.ballot.body_hash())).copied().unwrap_or(0) >= log.manifest.bond_zat)
        .map(|e| e.i)
        .collect())
}

fn attest(j: u32, secret: &Path, log_url: &str, bonds: &Path, out: &Path) -> Result<()> {
    let log = fetch_log(log_url)?;
    if log.close.is_none() {
        bail!("log is not closed yet");
    }
    let x = read_secret(j, secret, &log.manifest.committee.key)?;
    let bonded = bonded_indices(&log, bonds)?;
    let sig = BondAttestation::sign_member(&log.manifest.auction_id, &log.head(), &bonded, j, &x, &mut OsRng);
    fs::write(out, serde_json::to_string_pretty(&sig)?)?;
    println!("member {j} attests {} of {} entries bonded", bonded.len(), log.entries.len());
    Ok(())
}

fn post_bonds(log_url: &str, bonds: &Path, sigs: &[PathBuf]) -> Result<()> {
    let log = fetch_log(log_url)?;
    let bonded = bonded_indices(&log, bonds)?;
    let sigs: Vec<MemberSig> = sigs.iter().map(|p| Ok(serde_json::from_str(&fs::read_to_string(p)?)?)).collect::<Result<_>>()?;
    let att = BondAttestation { auction_id: log.manifest.auction_id, root: log.head(), bonded, sigs };
    if !att.verify(&log.manifest.committee.key) {
        bail!("signatures don't form a quorum over this bonded set");
    }
    post(log_url, "bonds", &att)?;
    println!("bonded set posted: {} entries", att.bonded.len());
    Ok(())
}

fn share(j: u32, secret: &Path, log_url: &str, target: &str, out: &Path) -> Result<()> {
    let log = fetch_log(log_url)?;
    if !log.next_targets()?.iter().any(|t| t == target) {
        bail!("clearing does not need {target} now; refusing to decrypt it");
    }
    let x = read_secret(j, secret, &log.manifest.committee.key)?;
    let ct = log.target_ciphertext(target).ok_or_else(|| anyhow!("unknown target"))?;
    let s = threshold::make_share(target, j, &x, &ct, &mut OsRng);
    fs::write(out, serde_json::to_string_pretty(&s)?)?;
    Ok(())
}

fn combine(log_url: &str, target: &str, shares: &[PathBuf]) -> Result<()> {
    let log = fetch_log(log_url)?;
    let ct = log.target_ciphertext(target).ok_or_else(|| anyhow!("unknown target"))?;
    let shares: Vec<DecryptionShare> = shares.iter().map(|p| Ok(serde_json::from_str(&fs::read_to_string(p)?)?)).collect::<Result<_>>()?;
    let rec = threshold::decrypt(target, &log.manifest.committee.key, &ct, shares, log.entries.len() as u64)?;
    post(log_url, "decryptions", &rec)?;
    println!("{target} decrypted and posted");
    Ok(())
}

fn clear(log_url: &str, members: &[String], block_hash: &str) -> Result<()> {
    let mut log = fetch_log(log_url)?;
    let key = log.manifest.committee.key.clone();
    let secrets = members
        .iter()
        .map(|m| {
            let (j, p) = m.split_once(':').ok_or_else(|| anyhow!("--member is j:path"))?;
            let j: u32 = j.parse()?;
            Ok((j, read_secret(j, Path::new(p), &key)?))
        })
        .collect::<Result<Vec<_>>>()?;
    if secrets.len() < key.t as usize {
        bail!("need at least t = {} members", key.t);
    }
    let max = log.entries.len() as u64;
    loop {
        let next = log.next_targets()?;
        if next.is_empty() {
            break;
        }
        for t in &next {
            let ct = log.target_ciphertext(t).ok_or_else(|| anyhow!("unknown target"))?;
            let shares = secrets.iter().map(|(j, x)| threshold::make_share(t, *j, x, &ct, &mut OsRng)).collect();
            let rec = threshold::decrypt(t, &key, &ct, shares, max)?;
            post(log_url, "decryptions", &rec)?;
            // Totals are public once posted; cells are counted, never printed.
            if t.starts_with("T_") {
                println!("{t} = {}", rec.m);
            }
        }
        let cells = next.iter().filter(|t| t.starts_with("ballot:")).count();
        if cells > 0 {
            println!("{cells} ballot cells decrypted");
        }
        log = fetch_log(log_url)?;
    }
    // Explorers show block hashes byte-reversed; the seed uses internal order.
    let mut bh = codec::bytes32_from_hex(block_hash).map_err(|_| anyhow!("bad block hash"))?;
    bh.reverse();
    let r = log.compute_result(bh)?;
    post(log_url, "result", &r)?;
    println!("result: {:?}, k* = {}, price = {:?} zat, {} winners", r.outcome, r.k_star, r.price_zat, r.winners.len());
    Ok(())
}

fn verify(log_url: &str) -> Result<()> {
    let log = fetch_log(log_url)?;
    let checks = auction::verify(&log);
    for c in &checks {
        println!("{} {} — {}", if c.ok { "PASS" } else { "FAIL" }, c.name, c.detail);
    }
    if checks.iter().all(|c| c.ok) {
        Ok(())
    } else {
        bail!("verification failed")
    }
}
