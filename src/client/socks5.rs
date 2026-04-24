use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::proto::Target;

pub enum SocksTarget {
    Connect(Target),
    UdpAssociate { udp_socket: UdpSocket },
}

pub async fn handshake(stream: &mut TcpStream) -> Result<SocksTarget> {
    // ── Greeting ───
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x5 {
        anyhow::bail!("not a SOCKS5 client (version byte = {})", hdr[0]);
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // Reply: no authentication required
    stream.write_all(&[0x5, 0x0]).await?;

    // ── Request ───
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 0x5 {
        anyhow::bail!("bad SOCKS5 request version {}", req[0]);
    }

    let cmd = req[1];
    if cmd != 0x1 && cmd != 0x3 {
        stream
            .write_all(&[0x5, 0x7, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
            .await?;
        anyhow::bail!("unsupported SOCKS5 command {}", cmd);
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
        t => anyhow::bail!("unsupported SOCKS5 address type {}", t),
    };
    let port = stream.read_u16().await?;

    if cmd == 0x1 {
        stream
            .write_all(&[0x5, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
            .await?;
        return Ok(SocksTarget::Connect(Target { host, port }));
    }

    // UDP ASSOCIATE (cmd == 0x3):
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = udp.local_addr()?;
    let mut reply = vec![0x5u8, 0x0, 0x0];
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
