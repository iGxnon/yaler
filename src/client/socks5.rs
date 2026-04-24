use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::proto::Target;

/// Result of a SOCKS5 handshake.
pub enum SocksTarget {
    /// Standard CONNECT tunnel.
    Connect(Target),
    /// UDP ASSOCIATE: caller receives a bound UDP socket.
    /// The original TCP control stream (passed to `handshake`) must remain
    /// open for the lifetime of the UDP association (per RFC 1928 §6).
    UdpAssociate { udp_socket: UdpSocket },
}

/// Perform the SOCKS5 server-side handshake on `stream` and return the target.
/// After this call the stream carries raw TCP data (CONNECT) or acts as a
/// control channel that must remain open (UDP ASSOCIATE).
pub async fn handshake(stream: &mut TcpStream) -> Result<SocksTarget> {
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

    // ── Request ───────────────────────────────────────────────────────────────
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 5 {
        return Err(anyhow!("bad SOCKS5 request version"));
    }

    let cmd = req[1];
    if cmd != 1 && cmd != 3 {
        stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(anyhow!("unsupported SOCKS5 command {}", cmd));
    }

    // Read destination address (ignored for UDP ASSOCIATE but required by protocol)
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

    if cmd == 1 {
        // CONNECT: reply success, bound address 0.0.0.0:0
        stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Ok(SocksTarget::Connect(Target { host, port }));
    }

    // UDP ASSOCIATE (cmd == 3):
    // Bind a local UDP socket and advertise its address to the SOCKS5 client.
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = udp.local_addr()?;
    let mut reply = vec![5u8, 0, 0];
    reply.extend_from_slice(&encode_socks5_addr(local_addr));
    stream.write_all(&reply).await?;

    // The SOCKS5 client now sends UDP datagrams to local_addr.
    // Caller must keep the ctrl TcpStream alive — when it closes, the
    // UDP association is terminated (RFC 1928 §6).
    let _ = (host, port); // client's advertised bind hint — not enforced
    Ok(SocksTarget::UdpAssociate { udp_socket: udp })
}

fn encode_socks5_addr(addr: SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut buf = vec![0x01u8];
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
            buf
        }
        SocketAddr::V6(v6) => {
            let mut buf = vec![0x04u8];
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
            buf
        }
    }
}
