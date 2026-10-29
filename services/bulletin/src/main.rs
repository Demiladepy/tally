//! tally-bulletin [--listen 127.0.0.1:8787] [--data ./bulletin-data] [--key ./bulletin.key] [--web ./web]
//!                [--lightwalletd https://testnet.zec.rocks:443]
//!
//! With --lightwalletd, the desk polls that server for the chain tip and
//! serves it at /v1/chain. It sends nothing about users or auctions.
//!
//! The key file holds the bulletin's receipt-signing scalar (hex). It is
//! created on first run. Keep it out of git.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use tally_bulletin::{Bulletin, ChainTip, Tip};
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

    let web = args.windows(2).find(|w| w[0] == "--web").map(|w| PathBuf::from(&w[1]));
    let chain = ChainTip::default();
    if let Some(url) = args.windows(2).find(|w| w[0] == "--lightwalletd").map(|w| w[1].clone()) {
        tokio::spawn(poll_tip(url, chain.clone()));
    }
    let app = Bulletin::new(sk, Some(data))?.with_chain(chain).router_with_web(web);
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    // The one line this service ever prints. No per-request output.
    println!("tally-bulletin listening on {listen}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Keep the chain tip fresh. Errors are retried quietly: the desk works
/// without it, and the web app just hides the countdown.
async fn poll_tip(url: String, chain: ChainTip) {
    use zcash_client_backend::proto::service::{compact_tx_streamer_client::CompactTxStreamerClient, ChainSpec};
    let mut first: Option<(u64, u64)> = None;
    loop {
        let height = async {
            let endpoint = tonic::transport::Endpoint::from_shared(url.clone())?
                .tls_config(tonic::transport::ClientTlsConfig::new().with_webpki_roots())?
                .timeout(std::time::Duration::from_secs(15));
            let mut client = CompactTxStreamerClient::new(endpoint.connect().await?);
            anyhow::Ok(client.get_latest_block(ChainSpec {}).await?.into_inner().height)
        }
        .await;
        if let Ok(height) = height {
            let seen_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            let (h0, t0) = *first.get_or_insert((height, seen_at));
            let secs_per_block = (height >= h0 + 20).then(|| (seen_at - t0) as f64 / (height - h0) as f64);
            if let Ok(mut tip) = chain.write() {
                *tip = Some(Tip { height, seen_at, secs_per_block });
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }
}
