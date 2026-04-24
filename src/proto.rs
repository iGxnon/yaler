use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// Binary frame types used inside WebSocket Binary messages.
/// Every Binary frame is prefixed with one of these bytes.
pub const FRAME_DATA: u8 = 0x00;
pub const FRAME_EOF: u8 = 0x01;
/// Random-length padding frame — receiver must discard. Used to obscure
/// traffic patterns by adding noise to frame size distributions.
pub const FRAME_PADDING: u8 = 0x02;
/// UDP datagram frame. Format: [FRAME_UDP, atyp(1), addr(?), port(2), payload...]
/// atyp=1 IPv4 (4 bytes), atyp=4 IPv6 (16 bytes), atyp=3 domain (1+n bytes).
pub const FRAME_UDP: u8 = 0x03;

/// First WebSocket frame (text) sent by the client to the server.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectReq {
    pub pw: String,
    pub host: String,
    pub port: u16,
    /// When true, this connection enters UDP relay mode instead of TCP tunnel.
    /// host/port are ignored in UDP mode.
    #[serde(default)]
    pub udp: bool,
}

/// Server reply to ConnectReq.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectResp {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

impl ConnectResp {
    pub fn ok() -> Self {
        Self {
            ok: true,
            err: None,
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            err: Some(msg.into()),
        }
    }
}

/// Resolved proxy target.
#[derive(Debug)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

/// Encode a UDP destination into FRAME_UDP wire format (atyp + addr + port).
/// Returns the encoded bytes WITHOUT the leading FRAME_UDP byte.
pub fn encode_udp_addr(addr: IpAddr, port: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    match addr {
        IpAddr::V4(v4) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(0x04);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

/// Decode the address/port prefix from a FRAME_UDP payload (after the FRAME_UDP byte).
/// Returns (IpAddr, port, payload_offset).
pub fn decode_udp_addr(data: &[u8]) -> Result<(IpAddr, u16, usize)> {
    if data.is_empty() {
        return Err(anyhow!("empty UDP frame"));
    }
    match data[0] {
        0x01 => {
            if data.len() < 7 {
                return Err(anyhow!("UDP frame too short for IPv4"));
            }
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((IpAddr::V4(ip), port, 7))
        }
        0x04 => {
            if data.len() < 19 {
                return Err(anyhow!("UDP frame too short for IPv6"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((IpAddr::V6(ip), port, 19))
        }
        t => Err(anyhow!("unsupported UDP atyp {t}")),
    }
}
