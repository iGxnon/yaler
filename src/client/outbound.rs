use anyhow::{Context, Result};
use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use std::future::poll_fn;
use tokio::net::TcpStream;

use crate::proto::Target;

pub type H2Streams = (h2::SendStream<Bytes>, h2::RecvStream);

/// Establish an HTTP/2 CONNECT tunnel to the remote server with a Chrome-like
/// TLS fingerprint.  Returns the two h2 stream halves ready for relay.
///
/// Metadata (password, target host/port) is carried in HTTP headers so it
/// works transparently through HTTP/2-aware middleboxes.
pub async fn connect(
    server: &str,
    port: u16,
    sni: &str,
    skip_verify: bool,
    password: &str,
    target: &Target,
) -> Result<H2Streams> {
    let tcp = TcpStream::connect(format!("{server}:{port}"))
        .await
        .with_context(|| format!("TCP connect to {server}:{port}"))?;

    let ssl_cfg = build_ssl_config(sni, skip_verify)?;
    let tls = tokio_boring::connect(ssl_cfg, sni, tcp)
        .await
        .map_err(|e| anyhow::anyhow!("TLS handshake: {e:#}"))?;

    let (mut client, h2_conn) = h2::client::Builder::new()
        .initial_window_size(1 << 20)
        .initial_connection_window_size(2 << 20)
        .handshake::<_, Bytes>(tls)
        .await
        .context("HTTP/2 handshake")?;

    tokio::spawn(async move {
        if let Err(e) = h2_conn.await {
            tracing::debug!("h2 connection driver: {e:#}");
        }
    });

    poll_fn(|cx| client.poll_ready(cx))
        .await
        .context("h2 client poll_ready")?;

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{}:{}", sni, port))
        .header("x-pw", password)
        .header("x-host", &target.host)
        .header("x-port", target.port.to_string())
        .body(())
        .context("build CONNECT request")?;

    let (resp_future, send) = client
        .send_request(req, false)
        .context("send CONNECT request")?;

    let resp = resp_future.await.context("await CONNECT response")?;

    if resp.status() != StatusCode::OK {
        return Err(anyhow::anyhow!(
            "server rejected tunnel to {}:{} — {}",
            target.host,
            target.port,
            resp.status()
        ));
    }

    let recv = resp.into_body();
    Ok((send, recv))
}

/// Build a BoringSSL ConnectConfiguration with Chrome-like TLS fingerprint.
fn build_ssl_config(sni: &str, skip_verify: bool) -> Result<boring::ssl::ConnectConfiguration> {
    let mut builder =
        SslConnector::builder(SslMethod::tls_client()).context("SslConnector builder")?;

    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    builder.set_cipher_list(concat!(
        "ECDHE-ECDSA-AES128-GCM-SHA256:",
        "ECDHE-RSA-AES128-GCM-SHA256:",
        "ECDHE-ECDSA-AES256-GCM-SHA384:",
        "ECDHE-RSA-AES256-GCM-SHA384:",
        "ECDHE-ECDSA-CHACHA20-POLY1305:",
        "ECDHE-RSA-CHACHA20-POLY1305:",
        "ECDHE-RSA-AES128-SHA:",
        "ECDHE-RSA-AES256-SHA:",
        "AES128-GCM-SHA256:",
        "AES256-GCM-SHA384:",
        "AES128-SHA:",
        "AES256-SHA"
    ))?;

    // HTTP/2 requires h2 in ALPN
    builder.set_alpn_protos(b"\x02h2")?;

    builder.set_default_verify_paths()?;

    if skip_verify {
        builder.set_verify(SslVerifyMode::NONE);
    }

    let connector = builder.build();
    let mut config = connector.configure().context("SslConnector configure")?;
    config.set_verify_hostname(!skip_verify);
    let _ = sni;
    Ok(config)
}
