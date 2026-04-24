mod handler;
pub mod udp;

use anyhow::Result;
use axum::{
    extract::{FromRequestParts, Request, State, WebSocketUpgrade},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::any,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use std::sync::Arc;
use tracing::info;

use crate::config::ServerConfig;

#[derive(Clone)]
struct AppState {
    password: Arc<String>,
}

pub async fn run(cfg: ServerConfig) -> Result<()> {
    let state = AppState {
        password: Arc::new(cfg.password.clone()),
    };

    let path = cfg.path.clone();
    let app = Router::new()
        .route(&path, any(ws_handler))
        .fallback(fallback_handler)
        .with_state(state);

    let tls = build_tls_config(&cfg).await?;

    info!("server listening on {}", cfg.listen);
    axum_server::bind_rustls(cfg.listen.parse()?, tls)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn ws_handler(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, _body) = req.into_parts();
    match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(ws) => {
            let pw = state.password.as_ref().clone();
            ws.on_upgrade(move |socket| handler::handle(socket, pw))
        }
        Err(_) => fallback_handler().await.into_response(),
    }
}

/// Return a realistic nginx default page for any non-WebSocket request.
/// This defeats active probing: the server looks like a normal HTTPS site.
async fn fallback_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            ("content-type", "text/html; charset=utf-8"),
            ("server", "nginx/1.24.0"),
            ("x-content-type-options", "nosniff"),
        ],
        Html(NGINX_DEFAULT_PAGE),
    )
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

async fn build_tls_config(cfg: &ServerConfig) -> Result<RustlsConfig> {
    match (&cfg.cert, &cfg.key) {
        (Some(cert), Some(key)) => Ok(RustlsConfig::from_pem_file(cert, key).await?),
        _ => {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
            let cert_pem = cert.serialize_pem()?;
            let key_pem = cert.serialize_private_key_pem();
            tracing::warn!("using auto-generated self-signed certificate");
            Ok(RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes()).await?)
        }
    }
}
