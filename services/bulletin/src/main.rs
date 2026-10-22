//! tally-bulletin [--listen 127.0.0.1:8787] [--data ./bulletin-data] [--key ./bulletin.key]
//!
//! The key file holds the bulletin's receipt-signing scalar (hex). It is
//! created on first run. Keep it out of git.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use tally_bulletin::Bulletin;
use tally_crypto::codec;

fn arg(args: &[String], name: &str, default: &str) -> String {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
        .unwrap_or_else(|| default.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let listen = arg(&args, "--listen", "127.0.0.1:8787");
    let data = PathBuf::from(arg(&args, "--data", "./bulletin-data"));
    let key_path = PathBuf::from(arg(&args, "--key", "./bulletin.key"));

    let sk = if key_path.exists() {
        codec::scalar_from_hex(std::fs::read_to_string(&key_path)?.trim()).map_err(|e| anyhow!("key file: {e}"))?
    } else {
        let sk = tally_crypto::random_scalar(&mut rand_core::OsRng);
        std::fs::write(&key_path, codec::scalar_to_hex(&sk)).context("write key file")?;
        sk
    };

    let app = Bulletin::new(sk, Some(data))?.router();
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    // The one line this service ever prints. No per-request output.
    println!("tally-bulletin listening on {listen}");
    axum::serve(listener, app).await?;
    Ok(())
}
