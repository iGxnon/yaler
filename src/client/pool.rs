use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::outbound::WsStream;

/// A pool of idle WebSocket connections to the remote server.
///
/// After a tunnel session ends cleanly the caller returns the connection here;
/// the next request picks it up instead of paying for a new TLS handshake.
pub struct Pool {
    idle: Arc<Mutex<VecDeque<WsStream>>>,
    max_idle: usize,
}

impl Pool {
    pub fn new(max_idle: usize) -> Self {
        Self {
            idle: Arc::new(Mutex::new(VecDeque::new())),
            max_idle,
        }
    }

    /// Take an idle connection from the pool, if any.
    pub async fn get(&self) -> Option<WsStream> {
        self.idle.lock().await.pop_front()
    }

    /// Return a connection to the pool. If the pool is already full the
    /// connection is dropped (which closes the underlying WebSocket).
    pub async fn put(&self, conn: WsStream) {
        let mut idle = self.idle.lock().await;
        if idle.len() < self.max_idle {
            idle.push_back(conn);
        }
    }
}
