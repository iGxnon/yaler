use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proto::Target;

/// Result of parsing an HTTP proxy request.
pub enum HttpRequest {
    /// CONNECT tunnel — stream is now raw TCP after the 200 reply.
    Connect(Target),
    /// Plain HTTP forwarding — the full raw request bytes must be forwarded
    /// to the target before switching to bidirectional relay.
    Forward { target: Target, raw: Vec<u8> },
}

/// Read one HTTP proxy request from `stream`.
///
/// Handles both `CONNECT host:port` (HTTPS tunnel) and
/// `GET http://host/path` (plain HTTP forwarding).
pub async fn handshake(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut tmp = [0u8; 1];

    loop {
        stream.read_exact(&mut tmp).await?;
        buf.push(tmp[0]);
        if buf.ends_with(b"\r\n\r\n") || buf.ends_with(b"\n\n") {
            break;
        }
        if buf.len() > 16384 {
            return Err(anyhow!("HTTP headers too large"));
        }
    }

    let text = std::str::from_utf8(&buf)?;
    let first_line = text.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().ok_or_else(|| anyhow!("empty HTTP request"))?;

    if method.eq_ignore_ascii_case("CONNECT") {
        // ── CONNECT tunnel ──────────────────────────────────────────────────
        let addr = parts
            .next()
            .ok_or_else(|| anyhow!("missing address in CONNECT"))?;
        let target = parse_host_port(addr, 443)?;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        Ok(HttpRequest::Connect(target))
    } else {
        // ── Plain HTTP forwarding ────────────────────────────────────────────
        // e.g. GET http://example.com/path HTTP/1.1
        let url = parts
            .next()
            .ok_or_else(|| anyhow!("missing URL in {method}"))?;
        let target = parse_absolute_url(url)?;

        // Rewrite the request line to strip the absolute URI → relative path,
        // then forward the rest of the headers verbatim.
        let path = extract_path(url);
        let version = parts.next().unwrap_or("HTTP/1.1");
        let rest = text
            .splitn(2, '\n')
            .nth(1)
            .unwrap_or("")
            .trim_start_matches('\r');
        let rewritten = format!("{method} {path} {version}\r\n{rest}");

        Ok(HttpRequest::Forward {
            target,
            raw: rewritten.into_bytes(),
        })
    }
}

fn parse_host_port(addr: &str, default_port: u16) -> Result<Target> {
    let (host, port) = if let Some((h, p)) = addr.rsplit_once(':') {
        (h.to_string(), p.parse()?)
    } else {
        (addr.to_string(), default_port)
    };
    Ok(Target { host, port })
}

fn parse_absolute_url(url: &str) -> Result<Target> {
    // Strip scheme
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let host_part = rest.split('/').next().unwrap_or(rest);
    let default_port = if url.starts_with("https://") { 443 } else { 80 };
    parse_host_port(host_part, default_port)
}

fn extract_path(url: &str) -> &str {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    match rest.find('/') {
        Some(i) => &rest[i..],
        None => "/",
    }
}
