use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use super::outbound::WsStream;

const IDLE_TTL: Duration = Duration::from_secs(60);

struct Entry {
    ws: WsStream,
    added_at: Instant,
}

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

    pub async fn get(&self) -> Option<WsStream> {
        let mut idle = self.idle.lock().await;
        loop {
            let entry = idle.pop_front()?;
            if entry.added_at.elapsed() < IDLE_TTL {
                return Some(entry.ws);
            }
        }
    }

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
