/// Resolved proxy target extracted from the inbound handshake (SOCKS5 / HTTP CONNECT).
///
/// Passed to the outbound module as HTTP/2 CONNECT headers.
#[derive(Debug)]
pub struct Target {
    pub host: String,
    pub port: u16,
}
