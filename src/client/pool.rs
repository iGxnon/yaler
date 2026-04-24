use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use super::outbound::WsStream;

/// Idle connections expire after this duration to avoid using half-closed sockets.
const IDLE_TTL: Duration = Duration::from_secs(60);

struct Entry {
    ws: WsStream,
    added_at: Instant,
}

/// A pool of idle WebSocket connections to the remote server.
///
/// After a tunnel session ends cleanly the caller returns the connection here;
/// the next request picks it up instead of paying for a new TLS handshake.
/// Connections are discarded when they exceed IDLE_TTL, preventing stale
/// half-closed sockets from causing spurious errors.
pub struct Pool {
    idle: Arc<Mutex<VecDeque<Entry>>>,
    max_idle: usize,
}

impl Pool {
    pub fn new(max_idle: usize) -> Self {
        Self {
            idle: Arc::new(Mutex::new(VecDeque::new())),
            max_idle,
        }
    }

    /// Take a fresh-enough idle connection from the pool, if any.
    /// Expired connections are silently discarded.
    pub async fn get(&self) -> Option<WsStream> {
        let mut idle = self.idle.lock().await;
        loop {
            let entry = idle.pop_front()?;
            if entry.added_at.elapsed() < IDLE_TTL {
                return Some(entry.ws);
            }
            // Discard expired entry and try the next one.
        }
    }

    /// Return a connection to the pool.  If the pool is already full the
    /// connection is dropped (which closes the underlying WebSocket).
    pub async fn put(&self, ws: WsStream) {
        let mut idle = self.idle.lock().await;
        if idle.len() < self.max_idle {
            idle.push_back(Entry {
                ws,
                added_at: Instant::now(),
            });
        }
    }
}
