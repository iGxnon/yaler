use std::future::Future;
use std::time::Duration;

use anyhow::{anyhow, Result};
use axum::extract::ws;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite, WebSocketStream};

use crate::proto::{FRAME_DATA, FRAME_EOF, FRAME_PADDING};

pub enum WsRecv {
    Data(Vec<u8>),
    Closed,
    Err(anyhow::Error),
}

/// Abstracts over axum's WebSocket and tungstenite's WebSocketStream so that
/// relay_session can be shared between the server and client without duplication.
pub trait WsTunnel: Send {
    fn ws_recv(&mut self) -> impl Future<Output = WsRecv> + Send + '_;
    fn ws_send(&mut self, data: Vec<u8>) -> impl Future<Output = Result<()>> + Send + '_;
}

impl<S> WsTunnel for WebSocketStream<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    async fn ws_recv(&mut self) -> WsRecv {
        loop {
            match StreamExt::next(self).await {
                None => return WsRecv::Closed,
                Some(Ok(tungstenite::Message::Binary(b))) => return WsRecv::Data(b),
                Some(Ok(tungstenite::Message::Close(_))) => return WsRecv::Closed,
                Some(Ok(_)) => continue,
                Some(Err(e)) => return WsRecv::Err(e.into()),
            }
        }
    }

    async fn ws_send(&mut self, data: Vec<u8>) -> Result<()> {
        SinkExt::send(self, tungstenite::Message::Binary(data))
            .await
            .map_err(Into::into)
    }
}

impl WsTunnel for ws::WebSocket {
    async fn ws_recv(&mut self) -> WsRecv {
        loop {
            match ws::WebSocket::recv(self).await {
                None => return WsRecv::Closed,
                Some(Ok(ws::Message::Binary(b))) => return WsRecv::Data(b.to_vec()),
                Some(Ok(ws::Message::Close(_))) => return WsRecv::Closed,
                Some(Ok(_)) => continue,
                Some(Err(e)) => return WsRecv::Err(e.into()),
            }
        }
    }

    async fn ws_send(&mut self, data: Vec<u8>) -> Result<()> {
        self.send(ws::Message::Binary(Bytes::from(data)))
            .await
            .map_err(Into::into)
    }
}

/// Build a FRAME_PADDING frame with random content (8–128 bytes of padding).
/// The receiver discards these to obscure traffic size distributions.
fn make_padding_frame() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let pad_len: usize = rng.gen_range(8..=128);
    let mut frame = Vec::with_capacity(1 + pad_len);
    frame.push(FRAME_PADDING);
    frame.resize(1 + pad_len, 0u8);
    rng.fill(&mut frame[1..]);
    frame
}

/// Bidirectional relay between any WsTunnel and a TcpStream.
///
/// Binary frames are prefixed with FRAME_DATA or FRAME_EOF for application-level
/// session boundaries. FRAME_PADDING frames are injected randomly to obscure
/// traffic patterns and discarded on receipt. A small random jitter (0–8 ms) is
/// applied before forwarding TCP data into the WebSocket direction.
/// Returns Ok(()) with `ws` still open so the caller can return it to a pool.
pub async fn relay_session<W: WsTunnel>(ws: &mut W, tcp: TcpStream) -> Result<()> {
    let (mut tcp_rx, mut tcp_tx) = tcp.into_split();
    let mut buf = vec![0u8; 65536];
    let mut ws_eof = false;
    let mut tcp_eof = false;
    // Counter to decide when to inject a padding frame (roughly every N data frames).
    let mut frames_since_pad: u32 = 0;

    loop {
        if ws_eof && tcp_eof {
            break;
        }

        tokio::select! {
            frame = ws.ws_recv(), if !ws_eof => {
                match frame {
                    WsRecv::Data(data) => {
                        if data.is_empty() { continue; }
                        match data[0] {
                            FRAME_DATA => tcp_tx.write_all(&data[1..]).await?,
                            FRAME_EOF => {
                                tcp_tx.shutdown().await.ok();
                                ws_eof = true;
                            }
                            FRAME_PADDING => { /* discard noise */ }
                            _ => {}
                        }
                    }
                    WsRecv::Closed => return Err(anyhow!("WS connection closed unexpectedly")),
                    WsRecv::Err(e) => return Err(e),
                }
            }
            result = tcp_rx.read(&mut buf), if !tcp_eof => {
                let n = result?;
                if n == 0 {
                    ws.ws_send(vec![FRAME_EOF]).await?;
                    tcp_eof = true;
                } else {
                    // Random jitter 0–8 ms to obscure precise timing fingerprints.
                    let jitter_ms = rand::thread_rng().gen_range(0u64..=8);
                    if jitter_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
                    }

                    let mut frame = Vec::with_capacity(1 + n);
                    frame.push(FRAME_DATA);
                    frame.extend_from_slice(&buf[..n]);
                    ws.ws_send(frame).await?;

                    // Inject a padding frame roughly every 8–16 data frames.
                    frames_since_pad += 1;
                    let threshold = rand::thread_rng().gen_range(8u32..=16);
                    if frames_since_pad >= threshold {
                        ws.ws_send(make_padding_frame()).await?;
                        frames_since_pad = 0;
                    }
                }
            }
        }
    }

    Ok(())
}
