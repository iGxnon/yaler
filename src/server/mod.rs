mod handler;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use rustls::ServerConfig as RustlsServerConfig;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

use crate::config::ServerConfig;

pub async fn run(cfg: ServerConfig) -> Result<()> {
    let acceptor = build_tls_acceptor(&cfg)?;
    let listener = TcpListener::bind(&cfg.listen).await?;
    let password = Arc::new(cfg.password.clone());

    info!("server listening on {}", cfg.listen);

    loop {
        let (tcp, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let password = password.clone();

        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    error!("TLS accept: {e:#}");
                    return;
                }
            };
            if let Err(e) = serve_h2(tls, password).await {
                error!("h2 connection: {e:#}");
            }
        });
    }
}

async fn serve_h2<S>(stream: S, password: Arc<String>) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut conn = h2::server::Builder::new()
        .initial_window_size(1 << 20)
        .initial_connection_window_size(2 << 20)
        .enable_connect_protocol()
        .handshake::<_, Bytes>(stream)
        .await?;

    while let Some(result) = conn.accept().await {
        let (req, respond) = result?;
        let pw = password.as_ref().clone();
        tokio::spawn(async move {
            if let Err(e) = handler::handle(req, respond, pw).await {
                error!("handler: {e:#}");
            }
        });
    }

    Ok(())
}

fn build_tls_acceptor(cfg: &ServerConfig) -> Result<TlsAcceptor> {
    let (certs, key) = if let (Some(cert_path), Some(key_path)) = (&cfg.cert, &cfg.key) {
        let cert_pem = std::fs::read(cert_path)?;
        let key_pem = std::fs::read(key_path)?;
        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())?
            .ok_or_else(|| anyhow!("no private key in {key_path}"))?;
        (certs, key)
    } else {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        let cert_der = rustls::pki_types::CertificateDer::from(cert.serialize_der()?);
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            cert.serialize_private_key_der().into(),
        );
        tracing::warn!("using auto-generated self-signed certificate");
        (vec![cert_der], key_der)
    };

    let mut rustls_cfg = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    rustls_cfg.alpn_protocols = vec![b"h2".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(rustls_cfg)))
}
