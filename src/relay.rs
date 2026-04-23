use anyhow::Result;
use bytes::Bytes;
use std::future::poll_fn;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Bidirectional relay between an HTTP/2 stream and a raw TcpStream.
///
/// `send` / `recv` are the two halves of an h2 CONNECT stream (client or server side).
/// `tcp` is the raw TCP connection to the proxied target (server side) or the
/// local user application (client side).
pub async fn relay_h2_tcp(
    mut send: h2::SendStream<Bytes>,
    mut recv: h2::RecvStream,
    tcp: TcpStream,
) -> Result<()> {
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let mut buf = vec![0u8; 65536];

    let h2_to_tcp = async {
        loop {
            match poll_fn(|cx| recv.poll_data(cx)).await {
                Some(Ok(data)) => {
                    recv.flow_control().release_capacity(data.len())?;
                    tcp_w.write_all(&data).await?;
                }
                Some(Err(e)) => {
                    // RST_STREAM from the remote is a normal connection close, not an error.
                    if e.is_reset() {
                        break;
                    }
                    return Err(anyhow::anyhow!("h2 recv: {e:#}"));
                }
                None => break,
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    let tcp_to_h2 = async {
        loop {
            let n = tcp_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let chunk = Bytes::copy_from_slice(&buf[..n]);
            send.reserve_capacity(chunk.len());
            match poll_fn(|cx| send.poll_capacity(cx)).await {
                None | Some(Err(_)) => break, // stream closed by remote
                Some(Ok(_)) => {}
            }
            if send.send_data(chunk, false).is_err() {
                break; // remote reset the stream
            }
        }
        send.send_data(Bytes::new(), true).ok();
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r = h2_to_tcp => r,
        r = tcp_to_h2 => r,
    }
}
