use std::future::Future;

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite, WebSocketStream};

use crate::proto::{FRAME_DATA, FRAME_EOF};

pub enum WsRecv {
    Data(Vec<u8>),
    Closed,
    Err(anyhow::Error),
}

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

/// Bidirectional relay between any WsTunnel and a TcpStream.
pub async fn relay_session<W: WsTunnel>(ws: &mut W, tcp: TcpStream) -> Result<()> {
    let (mut tcp_rx, mut tcp_tx) = tcp.into_split();
    let mut buf = vec![0u8; 65536];
    let mut ws_eof = false;
    let mut tcp_eof = false;

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
                    let mut frame = Vec::with_capacity(1 + n);
                    frame.push(FRAME_DATA);
                    frame.extend_from_slice(&buf[..n]);
                    ws.ws_send(frame).await?;
                }
            }
        }
    }

    Ok(())
}
