use anyhow::{Context, Result};
use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use tokio::net::TcpStream;
use tokio_tungstenite::{client_async, tungstenite, WebSocketStream};

pub type WsStream = WebSocketStream<tokio_boring::SslStream<TcpStream>>;

/// Connect to the remote server with a Chrome-like TLS fingerprint and upgrade
/// to WebSocket with browser-realistic HTTP headers.
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

    let config = build_ssl_config(skip_verify)?;
    let tls = tokio_boring::connect(config, sni, tcp)
        .await
        .map_err(|e| anyhow::anyhow!("TLS handshake: {e:#?}"))?;

    let request = build_ws_request(sni, port, path)?;

    let (ws, _) = client_async(request, tls)
        .await
        .context("WebSocket handshake")?;

    Ok(ws)
}

/// Build a WebSocket upgrade request that mimics what a real Chrome browser
/// sends, including Origin, User-Agent, and standard HTTP headers.
fn build_ws_request(
    sni: &str,
    port: u16,
    path: &str,
) -> Result<tungstenite::handshake::client::Request> {
    let url = if port == 443 {
        format!("wss://{sni}{path}")
    } else {
        format!("wss://{sni}:{port}{path}")
    };

    let origin = if port == 443 {
        format!("https://{sni}")
    } else {
        format!("https://{sni}:{port}")
    };

    let request = tungstenite::handshake::client::Request::builder()
        .uri(&url)
        .header("Host", sni)
        .header("Origin", origin)
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
             AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/124.0.0.0 Safari/537.36",
        )
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .body(())
        .context("build WebSocket request")?;

    Ok(request)
}

/// Build a BoringSSL `ConnectConfiguration` that mimics Chrome's TLS ClientHello.
///
/// Chrome is built on BoringSSL, so BoringSSL defaults already produce the
/// correct GREASE values and extension ordering.  We additionally pin the
/// cipher suite list and ALPN to match a recent Chrome release.
fn build_ssl_config(skip_verify: bool) -> Result<boring::ssl::ConnectConfiguration> {
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

    // Load system CA bundle so BoringSSL can verify real certificates.
    builder.set_default_verify_paths()?;

    if skip_verify {
        builder.set_verify(SslVerifyMode::NONE);
    }

    let connector = builder.build();
    let mut config = connector.configure().context("SslConnector configure")?;
    config.set_verify_hostname(!skip_verify);
    Ok(config)
}
