use anyhow::Result;
use futures_util::StreamExt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::{TcpStream, UdpSocket};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, warn};

use super::inbound::do_handshake;
use crate::config::ClientConfig;
use crate::proto::{decode_udp_addr, encode_udp_addr, ConnectReq, FRAME_UDP};

/// Maximum UDP datagram size we handle.
const MAX_UDP: usize = 65507;

/// SOCKS5 UDP request/response header parser.
/// Format: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT(2) | DATA
fn parse_socks5_udp(buf: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if buf.len() < 10 {
        return None;
    }
    // RSV must be 0x0000, FRAG must be 0 (no fragmentation)
    if buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
        return None;
    }
    let (addr, port, offset) = match buf[3] {
        0x01 => {
            if buf.len() < 10 {
                return None;
            }
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (IpAddr::V4(ip), port, 10)
        }
        0x04 => {
            if buf.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            (IpAddr::V6(ip), port, 22)
        }
        _ => return None, // domain addresses not supported in UDP relay
    };
    Some((SocketAddr::new(addr, port), &buf[offset..]))
}

/// Build a SOCKS5 UDP response wrapper around `payload` from `src`.
fn build_socks5_udp(src: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8, 0, 0]; // RSV + FRAG
    match src.ip() {
        IpAddr::V4(v4) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(0x04);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&src.port().to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Client-side UDP relay for SOCKS5 UDP ASSOCIATE.
///
/// - `udp_socket`: bound local UDP socket advertised to the SOCKS5 client.
/// - `ctrl`: the original SOCKS5 TCP control connection (kept alive until done).
/// - `cfg`: client configuration for connecting to the remote server.
///
/// Opens a fresh (non-pooled) WebSocket to the server in UDP relay mode,
/// then bridges UDP datagrams between the SOCKS5 app and the remote server.
pub async fn client_relay(
    udp_socket: UdpSocket,
    ctrl: TcpStream,
    cfg: &ClientConfig,
) -> Result<()> {
    let udp_req = ConnectReq {
        pw: cfg.password.clone(),
        host: String::new(),
        port: 0,
        udp: true,
    };
    let req_text = serde_json::to_string(&udp_req)?;

    let mut ws =
        super::outbound::connect(&cfg.server, cfg.port, &cfg.path, &cfg.sni, cfg.skip_verify)
            .await?;
    do_handshake(&mut ws, &req_text).await?;

    let mut udp_buf = vec![0u8; MAX_UDP];
    // Track the SOCKS5 client address from the first datagram.
    let mut client_addr: Option<SocketAddr> = None;

    // ctrl is kept alive here; when the SOCKS5 client closes the TCP
    // connection, `ctrl` drops and we exit.
    let mut ctrl = ctrl;

    loop {
        tokio::select! {
            // Ctrl connection closed → end UDP association.
            _ = async {
                let mut buf = [0u8; 1];
                tokio::io::AsyncReadExt::read(&mut ctrl, &mut buf).await
            } => {
                debug!("UDP ctrl connection closed, ending association");
                break;
            }

            // Datagram from SOCKS5 app → wrap and forward to server.
            res = udp_socket.recv_from(&mut udp_buf) => {
                let (n, from) = res?;
                client_addr = Some(from);
                let pkt = &udp_buf[..n];

                let (dst, payload) = match parse_socks5_udp(pkt) {
                    Some(v) => v,
                    None => { warn!("UDP: malformed SOCKS5 datagram, skipping"); continue; }
                };

                let mut frame = vec![FRAME_UDP];
                frame.extend_from_slice(&encode_udp_addr(dst.ip(), dst.port()));
                frame.extend_from_slice(payload);
                use futures_util::SinkExt;
                ws.send(Message::Binary(frame)).await?;
            }

            // Frame from server → unwrap and deliver to SOCKS5 app.
            msg = ws.next() => {
                let msg = match msg {
                    None => { warn!("UDP: WS closed by server"); break; }
                    Some(m) => m?,
                };
                let data = match msg {
                    Message::Binary(b) => b,
                    Message::Close(_) => break,
                    _ => continue,
                };
                if data.is_empty() || data[0] != FRAME_UDP {
                    continue;
                }
                let (src_ip, src_port, offset) = decode_udp_addr(&data[1..])?;
                let payload = &data[1 + offset..];
                let src_addr = SocketAddr::new(src_ip, src_port);

                if let Some(client) = client_addr {
                    let wrapped = build_socks5_udp(src_addr, payload);
                    udp_socket.send_to(&wrapped, client).await?;
                }
            }
        }
    }

    Ok(())
}
