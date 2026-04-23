use anyhow::{anyhow, Result};
use bytes::Bytes;
use h2::server::SendResponse;
use h2::RecvStream;
use http::{Method, Request, Response, StatusCode};
use tokio::net::TcpStream;
use tracing::info;

use crate::relay::relay_h2_tcp;

pub async fn handle(
    req: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    password: String,
) -> Result<()> {
    if req.method() != Method::POST {
        respond.send_response(
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(())
                .unwrap(),
            true,
        )?;
        return Err(anyhow!("method not allowed: {}", req.method()));
    }

    // Authenticate
    let pw = req
        .headers()
        .get("x-pw")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow!("missing x-pw header"))?;

    if pw != password {
        respond.send_response(
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(())
                .unwrap(),
            true,
        )?;
        return Err(anyhow!("unauthorized"));
    }

    // Extract target
    let host = req
        .headers()
        .get("x-host")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow!("missing x-host header"))?
        .to_string();
    let port: u16 = req
        .headers()
        .get("x-port")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow!("missing x-port header"))?
        .parse()?;

    let addr = format!("{host}:{port}");
    let tcp = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            respond.send_response(
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(())
                    .unwrap(),
                true,
            )?;
            return Err(anyhow!("connect {addr}: {e:#}"));
        }
    };

    info!("tunnel → {addr}");

    let send = respond.send_response(
        Response::builder().status(StatusCode::OK).body(()).unwrap(),
        false,
    )?;
    let recv = req.into_body();

    relay_h2_tcp(send, recv, tcp).await
}
