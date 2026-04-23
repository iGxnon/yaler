use anyhow::{anyhow, Result};
use axum::extract::ws::{Message, WebSocket};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{error, info};

use crate::proto::{ConnectReq, ConnectResp};

pub async fn handle(mut ws: WebSocket, password: String) {
    if let Err(e) = handle_inner(&mut ws, &password).await {
        error!("handler: {e}");
    }
}

async fn handle_inner(ws: &mut WebSocket, password: &str) -> Result<()> {
    // ── 1. Receive the connect request ──────────────────────────────────────
    let msg = ws
        .recv()
        .await
        .ok_or_else(|| anyhow!("connection closed before handshake"))??;

    let req: ConnectReq = match msg {
        Message::Text(t) => serde_json::from_str(t.as_str())?,
        _ => return Err(anyhow!("expected text frame for handshake")),
    };

    if req.pw != password {
        ws.send(Message::Text(
            serde_json::to_string(&ConnectResp::err("unauthorized"))?.into(),
        ))
        .await?;
        return Err(anyhow!("unauthorized client"));
    }

    // ── 2. Connect to the target ─────────────────────────────────────────────
    let addr = format!("{}:{}", req.host, req.port);
    let tcp = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            ws.send(Message::Text(
                serde_json::to_string(&ConnectResp::err(e.to_string()))?.into(),
            ))
            .await?;
            return Err(anyhow!("connect {addr}: {e}"));
        }
    };

    ws.send(Message::Text(
        serde_json::to_string(&ConnectResp::ok())?.into(),
    ))
    .await?;

    info!("tunnel → {addr}");
    relay(ws, tcp).await
}

async fn relay(ws: &mut WebSocket, tcp: TcpStream) -> Result<()> {
    let (mut tcp_rx, mut tcp_tx) = tcp.into_split();
    let mut buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            msg = ws.recv() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        tcp_tx.write_all(&data).await?;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e.into()),
                }
            }
            result = tcp_rx.read(&mut buf) => {
                let n = result?;
                if n == 0 {
                    break;
                }
                if ws
                    .send(Message::Binary(Bytes::copy_from_slice(&buf[..n])))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }

    Ok(())
}
