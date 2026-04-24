use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tracing::{error, info};
use tungstenite::Message;

use crate::proto::{ConnectReq, ConnectResp};
use crate::relay::relay_session;

pub async fn handle<S>(mut ws: WebSocketStream<S>, password: String)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    if let Err(e) = handle_inner(&mut ws, &password).await {
        error!("handler: {e:#}");
    }
}

fn password_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        let _ = a.iter().zip(a.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y));
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn handle_inner<S>(ws: &mut WebSocketStream<S>, password: &str) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    loop {
        let msg = match ws.next().await {
            None => return Ok(()),
            Some(m) => m?,
        };

        let req: ConnectReq = match msg {
            Message::Text(t) => serde_json::from_str(&t)?,
            Message::Close(_) => return Ok(()),
            _ => return Err(anyhow!("expected text frame for handshake")),
        };

        if !password_eq(&req.pw, password) {
            ws.send(Message::Text(
                serde_json::to_string(&ConnectResp::err("unauthorized"))?,
            ))
            .await?;
            return Err(anyhow!("unauthorized client"));
        }

        let addr = format!("{}:{}", req.host, req.port);
        let tcp = match TcpStream::connect(&addr).await {
            Ok(s) => s,
            Err(e) => {
                ws.send(Message::Text(
                    serde_json::to_string(&ConnectResp::err(e.to_string()))?,
                ))
                .await?;
                continue;
            }
        };

        ws.send(Message::Text(serde_json::to_string(&ConnectResp::ok())?))
            .await?;

        info!("tunnel → {addr}");
        relay_session(ws, tcp).await?;
    }
}
