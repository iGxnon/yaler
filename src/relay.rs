use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

/// Bidirectional relay between a tungstenite WebSocketStream and a raw TcpStream.
///
/// Used on the **client** side: ws is the tunnel to the remote server,
/// tcp is the inbound connection from the local user application.
pub async fn relay_ws_tcp<S>(ws: WebSocketStream<S>, tcp: TcpStream) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (mut tcp_rx, mut tcp_tx) = tcp.into_split();

    let ws_to_tcp = async move {
        while let Some(msg) = ws_rx.next().await {
            match msg? {
                Message::Binary(data) => tcp_tx.write_all(&data).await?,
                Message::Close(_) => break,
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    let tcp_to_ws = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = tcp_rx.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            ws_tx.send(Message::Binary(buf[..n].to_vec())).await?;
        }
        ws_tx.close().await.ok();
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r = ws_to_tcp => r,
        r = tcp_to_ws => r,
    }
}
