use anyhow::Result;
use axum::extract::ws::{Message, WebSocket};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::proto::{decode_udp_addr, encode_udp_addr, FRAME_UDP};

/// Server-side UDP relay: receives FRAME_UDP datagrams from the client WS,
/// sends them to the real destination via UDP, and forwards responses back.
///
/// Each unique (dst_ip, dst_port) gets its own UDP socket on the server.
/// Responses from all sockets are multiplexed back through the single WS.
pub async fn relay(ws: &mut WebSocket) -> Result<()> {
    // Channel for background receiver tasks to send responses back to the WS sender.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);

    // Map from destination SocketAddr to the corresponding UDP socket.
    let mut sockets: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();

    loop {
        tokio::select! {
            // Response from a background UDP receiver → forward to client.
            Some(frame) = rx.recv() => {
                ws.send(Message::Binary(frame.into())).await?;
            }

            // Datagram from client WS → forward via UDP.
            msg = ws.recv() => {
                let msg = match msg {
                    None => break,
                    Some(m) => m?,
                };
                let data = match msg {
                    Message::Binary(b) => b.to_vec(),
                    Message::Close(_) => break,
                    _ => continue,
                };
                if data.is_empty() || data[0] != FRAME_UDP {
                    continue;
                }
                let (dst_ip, dst_port, offset) = match decode_udp_addr(&data[1..]) {
                    Ok(v) => v,
                    Err(e) => { warn!("UDP server: bad frame addr: {e:#}"); continue; }
                };
                let payload = &data[1 + offset..];
                let dst = SocketAddr::new(dst_ip, dst_port);

                // Reuse or create a UDP socket for this destination.
                let sock = match sockets.get(&dst) {
                    Some(s) => Arc::clone(s),
                    None => {
                        let bind_addr = if dst_ip.is_ipv6() {
                            "[::]:0"
                        } else {
                            "0.0.0.0:0"
                        };
                        let s = Arc::new(UdpSocket::bind(bind_addr).await?);
                        s.connect(dst).await?;
                        debug!("UDP server: new socket → {dst}");
                        let s = Arc::clone(&{
                            sockets.insert(dst, s.clone());
                            s
                        });
                        // Spawn a background task to receive responses from this socket.
                        let tx2 = tx.clone();
                        tokio::spawn(recv_loop(s.clone(), dst_ip, dst_port, tx2));
                        s
                    }
                };

                if let Err(e) = sock.send(payload).await {
                    warn!("UDP server: send to {dst} failed: {e:#}");
                }
            }
        }
    }

    Ok(())
}

/// Background task: receive UDP responses from `socket` and send them back
/// as FRAME_UDP frames through `tx`.
async fn recv_loop(
    socket: Arc<UdpSocket>,
    src_ip: IpAddr,
    src_port: u16,
    tx: mpsc::Sender<Vec<u8>>,
) {
    let mut buf = vec![0u8; 65507];
    loop {
        match socket.recv(&mut buf).await {
            Ok(n) => {
                let mut frame = vec![FRAME_UDP];
                frame.extend_from_slice(&encode_udp_addr(src_ip, src_port));
                frame.extend_from_slice(&buf[..n]);
                if tx.send(frame).await.is_err() {
                    break; // WS gone, stop receiving
                }
            }
            Err(e) => {
                debug!("UDP server recv error from {src_ip}:{src_port}: {e:#}");
                break;
            }
        }
    }
}
