use anyhow::{anyhow, Result};
use axum::extract::ws::{Message, WebSocket};
use tokio::net::TcpStream;
use tracing::{error, info};

use crate::proto::{ConnectReq, ConnectResp};
use crate::relay::relay_session;

pub async fn handle(mut ws: WebSocket, password: String) {
    if let Err(e) = handle_inner(&mut ws, &password).await {
        error!("handler: {e:#}");
    }
}

/// Loop over sequential tunnel sessions on the same WebSocket connection.
/// Each iteration performs the ConnectReq handshake and then relays data.
/// Returning Ok(()) from a relay means the session ended cleanly; we loop
/// back so the client can reuse the connection for the next request.
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

        if req.pw != password {
            ws.send(Message::Text(
                serde_json::to_string(&ConnectResp::err("unauthorized"))?.into(),
            ))
            .await?;
            return Err(anyhow!("unauthorized client"));
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
