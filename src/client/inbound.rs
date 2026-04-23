use anyhow::Result;
use bytes::Bytes;
use std::future::poll_fn;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

use super::http::HttpRequest;
use crate::config::ClientConfig;
use crate::proto::Target;
use crate::relay::relay_h2_tcp;

pub async fn run(cfg: ClientConfig) -> Result<()> {
    let listener = TcpListener::bind(&cfg.listen).await?;
    info!("client listening on {} (HTTP CONNECT + SOCKS5)", cfg.listen);

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, cfg).await {
                error!("connection from {peer}: {e:#}");
            }
        });
    }
}

async fn handle(mut stream: TcpStream, cfg: ClientConfig) -> Result<()> {
    let mut peek = [0u8; 1];
    stream.peek(&mut peek).await?;

    let (target, prefix): (Target, Vec<u8>) = if peek[0] == 0x05 {
        (super::socks5::handshake(&mut stream).await?, vec![])
    } else {
        match super::http::handshake(&mut stream).await? {
            HttpRequest::Connect(t) => (t, vec![]),
            HttpRequest::Forward { target, raw } => (target, raw),
        }
    };

    info!("proxying {}:{}", target.host, target.port);

    let (mut send, recv) = super::outbound::connect(
        &cfg.server,
        cfg.port,
        &cfg.sni,
        cfg.skip_verify,
        &cfg.password,
        &target,
    )
    .await?;

    // For plain HTTP forwarding, send the rewritten request as the first data chunk.
    if !prefix.is_empty() {
        send.reserve_capacity(prefix.len());
        poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| anyhow::anyhow!("h2 send stream closed"))??;
        send.send_data(Bytes::from(prefix), false)
            .map_err(|e| anyhow::anyhow!("send prefix: {e:#}"))?;
    }

    relay_h2_tcp(send, recv, stream).await
}
