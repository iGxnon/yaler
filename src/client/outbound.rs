use anyhow::{Context, Result};
use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use tokio::net::TcpStream;
use tokio_tungstenite::{client_async, tungstenite::client::IntoClientRequest, WebSocketStream};

pub type WsStream = WebSocketStream<tokio_boring::SslStream<TcpStream>>;

/// Connect to the remote server with a Chrome-like TLS fingerprint and upgrade
/// to WebSocket.  Returns the WebSocketStream ready for the tunnel handshake.
pub async fn connect(
    server: &str,
    port: u16,
    path: &str,
    sni: &str,
    skip_verify: bool,
) -> Result<WsStream> {
    let tcp = TcpStream::connect(format!("{server}:{port}"))
        .await
        .with_context(|| format!("TCP connect to {server}:{port}"))?;

    let config = build_ssl_config(sni, skip_verify)?;
    let tls = tokio_boring::connect(config, sni, tcp)
        .await
        .map_err(|e| anyhow::anyhow!("TLS handshake: {e:#?}"))?;

    let url = format!("wss://{}:{}{}", sni, port, path);
    let request = url
        .into_client_request()
        .context("build WebSocket request")?;

    let (ws, _) = client_async(request, tls)
        .await
        .context("WebSocket handshake")?;

    Ok(ws)
}

/// Build a BoringSSL `ConnectConfiguration` that mimics Chrome's TLS ClientHello.
///
/// Chrome is built on BoringSSL, so BoringSSL defaults already produce the
/// correct GREASE values and extension ordering.  We additionally pin the
/// cipher suite list and ALPN to match a recent Chrome release.
fn build_ssl_config(sni: &str, skip_verify: bool) -> Result<boring::ssl::ConnectConfiguration> {
    let mut builder =
        SslConnector::builder(SslMethod::tls_client()).context("SslConnector builder")?;

    // TLS 1.2–1.3 only (Chrome dropped TLS 1.0/1.1)
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // Chrome TLS 1.2 cipher suite order (as of Chrome 120+)
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

    // WebSocket requires HTTP/1.1 upgrade; offering h2 causes Cloudflare and
    // other HTTP/2 middleboxes to negotiate h2 and reject the WS handshake.
    builder.set_alpn_protos(b"\x08http/1.1")?;

    // Load system CA bundle so BoringSSL can verify real certificates
    // (e.g. Let's Encrypt). Without this BoringSSL has an empty trust store.
    builder.set_default_verify_paths()?;

    if skip_verify {
        builder.set_verify(SslVerifyMode::NONE);
    }

    let connector = builder.build();
    let mut config = connector.configure().context("SslConnector configure")?;
    config.set_verify_hostname(!skip_verify);
    // SNI is passed separately to tokio_boring::connect
    let _ = sni;
    Ok(config)
}
