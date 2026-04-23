use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info};

use crate::config::ClientConfig;
use crate::proto::{ConnectReq, ConnectResp, Target};
use crate::relay::relay_ws_tcp;
use super::http::HttpRequest;

pub async fn run(cfg: ClientConfig) -> Result<()> {
    let listener = TcpListener::bind(&cfg.listen).await?;
    info!("client listening on {} (HTTP CONNECT + SOCKS5)", cfg.listen);

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, cfg).await {
                error!("connection from {peer}: {e}");
            }
        });
    }
}

async fn handle(mut stream: TcpStream, cfg: ClientConfig) -> Result<()> {
    let mut peek = [0u8; 1];
    stream.peek(&mut peek).await?;

    // Dispatch by protocol: SOCKS5 starts with 0x05, everything else is HTTP.
    let (target, prefix): (Target, Vec<u8>) = if peek[0] == 0x05 {
        (super::socks5::handshake(&mut stream).await?, vec![])
    } else {
        match super::http::handshake(&mut stream).await? {
            HttpRequest::Connect(t) => (t, vec![]),
            HttpRequest::Forward { target, raw } => (target, raw),
        }
    };

    info!("proxying {}:{}", target.host, target.port);

    // ── Open WebSocket tunnel to the remote server ────────────────────────────
    let mut ws = super::outbound::connect(
        &cfg.server,
        cfg.port,
        &cfg.path,
        &cfg.sni,
        cfg.skip_verify,
    )
    .await?;

    let req = ConnectReq { pw: cfg.password.clone(), host: target.host.clone(), port: target.port };
    ws.send(Message::Text(serde_json::to_string(&req)?)).await?;

    let resp_msg = ws
        .next()
        .await
        .ok_or_else(|| anyhow!("server closed before responding"))??;
    match resp_msg {
        Message::Text(t) => {
            let resp: ConnectResp = serde_json::from_str(&t)?;
            if !resp.ok {
                return Err(anyhow!(
                    "server refused {}:{}: {}",
                    target.host,
                    target.port,
                    resp.err.unwrap_or_default()
                ));
            }
        }
        _ => return Err(anyhow!("unexpected message during tunnel handshake")),
    }

    // For plain HTTP forwarding, send the rewritten request before relay.
    if !prefix.is_empty() {
        ws.send(Message::Binary(prefix.into())).await?;
    }

    relay_ws_tcp(ws, stream).await
}
