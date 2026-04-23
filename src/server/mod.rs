mod handler;

use anyhow::Result;
use axum::{
    extract::{State, WebSocketUpgrade},
    response::Response,
    routing::get,
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
        .route(&path, get(ws_handler))
        .with_state(state);

    let tls = build_tls_config(&cfg).await?;

    info!("server listening on {}", cfg.listen);
    axum_server::bind_rustls(cfg.listen.parse()?, tls)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    let pw = state.password.as_ref().clone();
    ws.on_upgrade(move |socket| handler::handle(socket, pw))
}

async fn build_tls_config(cfg: &ServerConfig) -> Result<RustlsConfig> {
    match (&cfg.cert, &cfg.key) {
        (Some(cert), Some(key)) => Ok(RustlsConfig::from_pem_file(cert, key).await?),
        _ => {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
            let cert_pem = cert.serialize_pem()?;
            let key_pem = cert.serialize_private_key_pem();
            tracing::warn!("using auto-generated self-signed certificate");
            Ok(RustlsConfig::from_pem(
                cert_pem.into_bytes(),
                key_pem.into_bytes(),
            )
            .await?)
        }
    }
}
