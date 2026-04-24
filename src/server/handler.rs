use anyhow::{anyhow, Result};
use axum::extract::ws::{Message, WebSocket};
use tokio::net::TcpStream;
use tracing::{error, info};

use crate::proto::{ConnectReq, ConnectResp};
use crate::relay::relay_session;

pub async fn handle(mut ws: WebSocket, password: String) {
    if let Err(e) = handle_inner(&mut ws, &password).await {
        // BoringSSL (client) often closes the TCP connection without sending a
        // TLS close_notify when returning a connection to its pool. rustls is
        // strict about this per spec, but it is not a real error — treat it as
        // a normal close.
        let s = format!("{e:#}");
        if s.contains("close_notify") {
            return;
        }
        error!("handler: {e:#}");
    }
}

/// Constant-time byte comparison to prevent timing-based password guessing.
fn password_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        // Still run a dummy comparison to avoid immediate early-return on length.
        let _ = a
            .iter()
            .zip(a.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y));
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

async fn handle_inner(ws: &mut WebSocket, password: &str) -> Result<()> {
    loop {
        let msg = match ws.recv().await {
            None => return Ok(()),
            Some(m) => m?,
        };

        let req: ConnectReq = match msg {
            Message::Text(t) => serde_json::from_str(t.as_str())?,
            Message::Close(_) => return Ok(()),
            _ => return Err(anyhow!("expected text frame for handshake")),
        };

        if !password_eq(&req.pw, password) {
            ws.send(Message::Text(
                serde_json::to_string(&ConnectResp::err("unauthorized"))?.into(),
            ))
            .await?;
            return Err(anyhow!("unauthorized client"));
        }

        if req.udp {
            info!("UDP relay session started");
            crate::server::udp::relay(ws).await?;
            return Ok(());
        }

        let addr = format!("{}:{}", req.host, req.port);
        let tcp = match TcpStream::connect(&addr).await {
            Ok(s) => s,
            Err(e) => {
                ws.send(Message::Text(
                    serde_json::to_string(&ConnectResp::err(e.to_string()))?.into(),
                ))
                .await?;
                continue;
            }
        };

        ws.send(Message::Text(
            serde_json::to_string(&ConnectResp::ok())?.into(),
        ))
        .await?;

        info!("tunnel → {addr}");
        relay_session(ws, tcp).await?;
    }
}
