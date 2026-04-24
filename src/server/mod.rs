mod handler;

use std::convert::Infallible;
use std::sync::Arc;

use anyhow::Result;
use boring::ssl::{SslAcceptor as BoringAcceptor, SslFiletype, SslMethod};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::config::ServerConfig;
use crate::ssl::SslAcceptor;

pub async fn run(cfg: ServerConfig) -> Result<()> {
    let acceptor = Arc::new(build_tls_acceptor(&cfg)?);
    let listener = TcpListener::bind(&cfg.listen).await?;
    let cfg = Arc::new(cfg);

    info!("server listening on {}", cfg.listen);

    loop {
        let (tcp_stream, _addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let cfg = cfg.clone();

        tokio::spawn(async move {
            let ssl_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    error!("TLS handshake failed: {e}");
                    return;
                }
            };

            let io = TokioIo::new(ssl_stream);
            let connection = http1::Builder::new()
                .serve_connection(io, service_fn(move |req| handle_request(req, cfg.clone())))
                .with_upgrades();
            if let Err(e) = connection.await {
                error!("HTTP connection error: {e}");
            }
        });
    }
}

async fn handle_request(
    mut req: Request<Incoming>,
    cfg: Arc<ServerConfig>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() == cfg.path {
        if let Ok((response, websocket)) = hyper_tungstenite::upgrade(&mut req, None) {
            let password = cfg.password.clone();
            tokio::spawn(async move {
                match websocket.await {
                    Ok(ws) => handler::handle(ws, password).await,
                    Err(e) => error!("WS handshake error: {e}"),
                }
            });
            return Ok(response.map(|_| Full::new(Bytes::new())));
        }
    }

    Ok(nginx_response())
}

fn build_tls_acceptor(cfg: &ServerConfig) -> Result<SslAcceptor> {
    let mut builder = BoringAcceptor::mozilla_modern(SslMethod::tls())?;

    match (&cfg.cert, &cfg.key) {
        (Some(cert_path), Some(key_path)) => {
            builder.set_certificate_file(cert_path, SslFiletype::PEM)?;
            builder.set_private_key_file(key_path, SslFiletype::PEM)?;
        }
        _ => {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
            let cert_pem = cert.serialize_pem()?;
            let key_pem = cert.serialize_private_key_pem();
            warn!("using auto-generated self-signed certificate");
            let x509 = boring::x509::X509::from_pem(cert_pem.as_bytes())?;
            builder.set_certificate(&x509)?;
            let pkey = boring::pkey::PKey::private_key_from_pem(key_pem.as_bytes())?;
            builder.set_private_key(&pkey)?;
        }
    }

    Ok(SslAcceptor::new(builder.build()))
}

fn nginx_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("server", "nginx/1.24.0")
        .header("x-content-type-options", "nosniff")
        .body(Full::new(Bytes::from(NGINX_DEFAULT_PAGE)))
        .unwrap()
}

const NGINX_DEFAULT_PAGE: &str = r#"<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
"#;
