use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info, warn};

use super::http::HttpRequest;
use super::outbound::WsStream;
use super::pool::Pool;
use crate::config::ClientConfig;
use crate::proto::{ConnectReq, ConnectResp, Target, FRAME_DATA};
use crate::relay::relay_session;

pub async fn run(cfg: ClientConfig) -> Result<()> {
    let listener = TcpListener::bind(&cfg.listen).await?;
    let pool = Arc::new(Pool::new(cfg.pool_size));
    info!("client listening on {} (HTTP CONNECT + SOCKS5)", cfg.listen);

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg = cfg.clone();
        let pool = Arc::clone(&pool);
        tokio::spawn(async move {
            if let Err(e) = handle(stream, cfg, pool).await {
                error!("connection from {peer}: {e:#}");
            }
        });
    }
}

async fn handle(mut stream: TcpStream, cfg: ClientConfig, pool: Arc<Pool>) -> Result<()> {
    let mut peek = [0u8; 1];
    stream.peek(&mut peek).await?;

    let (target, prefix): (Target, Vec<u8>) = if peek[0] == 0x05 {
        (super::socks5::handshake(&mut stream).await?, vec![])
    } else {
        match super::http::handshake(&mut stream).await? {
            HttpRequest::Connect(t) => (t, vec![]), // https
            HttpRequest::Forward { target, raw } => (target, raw), // http
        }
    };

    info!("proxying {}:{}", target.host, target.port);

    let req = ConnectReq {
        pw: cfg.password.clone(),
        host: target.host.clone(),
        port: target.port,
    };

    let mut ws = acquire_tunnel(&cfg, &pool, &req).await?;

    if !prefix.is_empty() {
        let mut frame = Vec::with_capacity(1 + prefix.len());
        frame.push(FRAME_DATA);
        frame.extend_from_slice(&prefix);
        ws.send(Message::Binary(frame)).await?;
    }

    match relay_session(&mut ws, stream).await {
        Ok(()) => pool.put(ws).await,
        Err(e) => return Err(e),
    }

    Ok(())
}

/// Get a tunnel-ready WebSocket from the pool, or open a fresh one.
/// If a pooled connection turns out to be stale (handshake fails), it is
/// silently discarded and a new connection is established instead.
async fn acquire_tunnel(cfg: &ClientConfig, pool: &Pool, req: &ConnectReq) -> Result<WsStream> {
    let req_text = serde_json::to_string(req)?;

    if let Some(mut ws) = pool.get().await {
        match do_handshake(&mut ws, &req_text).await {
            Ok(()) => return Ok(ws),
            Err(e) => warn!("pooled connection stale ({e:#}), opening fresh"),
        }
    }

    let mut ws =
        super::outbound::connect(&cfg.server, cfg.port, &cfg.path, &cfg.sni, cfg.skip_verify)
            .await?;
    do_handshake(&mut ws, &req_text).await?;
    Ok(ws)
}

async fn do_handshake(ws: &mut WsStream, req_text: &str) -> Result<()> {
    ws.send(Message::Text(req_text.to_owned())).await?;

    let msg = ws
        .next()
        .await
        .ok_or_else(|| anyhow!("server closed before responding"))??;

    match msg {
        Message::Text(t) => {
            let resp: ConnectResp = serde_json::from_str(&t)?;
            if !resp.ok {
                return Err(anyhow!("server refused: {}", resp.err.unwrap_or_default()));
            }
            Ok(())
        }
        _ => Err(anyhow!("unexpected message during tunnel handshake")),
    }
}
