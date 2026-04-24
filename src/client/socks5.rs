use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proto::Target;

/// Perform the SOCKS5 server-side handshake on `stream` and return the
/// requested target.  After this call the stream carries raw TCP data.
pub async fn handshake(stream: &mut TcpStream) -> Result<Target> {
    // ── Greeting ─────────────────────────────────────────────────────────────
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 5 {
        return Err(anyhow!("not a SOCKS5 client (version byte = {})", hdr[0]));
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // Reply: no authentication required
    stream.write_all(&[5, 0]).await?;

    // ── Connect request ───────────────────────────────────────────────────────
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 5 {
        return Err(anyhow!("bad SOCKS5 request version"));
    }
    if req[1] != 1 {
        // Only CONNECT (0x01) is supported
        stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(anyhow!("unsupported SOCKS5 command {}", req[1]));
    }

    let host = match req[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            IpAddr::V4(Ipv4Addr::from(ip)).to_string()
        }
        0x03 => {
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain)?
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            IpAddr::V6(Ipv6Addr::from(ip)).to_string()
        }
        t => return Err(anyhow!("unsupported SOCKS5 address type {t}")),
    };

    let port = stream.read_u16().await?;

    // Reply: success, bound address 0.0.0.0:0
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;

    Ok(Target { host, port })
}
