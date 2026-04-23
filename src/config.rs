use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// "0.0.0.0:443"
    pub listen: String,
    /// Path to PEM cert file; omit to auto-generate a self-signed cert
    pub cert: Option<String>,
    /// Path to PEM key file
    pub key: Option<String>,
    /// Shared password for client authentication
    pub password: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:443".to_string(),
            cert: None,
            key: None,
            password: "changeme".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Local mixed-port listener (HTTP CONNECT + SOCKS5)
    pub listen: String,
    /// Remote server host or IP
    pub server: String,
    /// Remote server port
    pub port: u16,
    /// Shared password (must match server)
    pub password: String,
    /// TLS SNI hostname sent in ClientHello
    pub sni: String,
    /// Skip TLS certificate verification (dev only)
    #[serde(default)]
    pub skip_verify: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:1080".to_string(),
            server: "127.0.0.1".to_string(),
            port: 443,
            password: "changeme".to_string(),
            sni: "example.com".to_string(),
            skip_verify: false,
        }
    }
}
