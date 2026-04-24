use std::{
    borrow::Borrow,
    collections::{hash_map::Entry, HashMap},
    hash::{Hash, Hasher},
    num::NonZeroUsize,
    sync::Mutex,
};

use boring::ssl::{SslSession, SslVersion};
use lru::LruCache;

#[derive(Clone)]
pub struct TlsSession(pub SslSession);

impl TlsSession {
    #[inline]
    pub fn id(&self) -> &[u8] {
        self.0.id()
    }

    #[inline]
    pub fn time(&self) -> u64 {
        self.0.time()
    }

    #[inline]
    pub fn timeout(&self) -> u32 {
        self.0.timeout()
    }

    #[inline]
    pub fn protocol_version(&self) -> SslVersion {
        return self.0.protocol_version();
    }
}

impl Eq for TlsSession {}

impl PartialEq for TlsSession {
    #[inline]
    fn eq(&self, other: &TlsSession) -> bool {
        self.0.id() == other.0.id()
    }
}

impl Hash for TlsSession {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.id().hash(state);
    }
}

impl Borrow<[u8]> for TlsSession {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.0.id()
    }
}

pub struct TlsSessionCache {
    inner: Mutex<Inner>,
    per_host_session_capacity: usize,
}

struct Inner {
    reverse: HashMap<TlsSession, String>,
    per_host_sessions: HashMap<String, LruCache<TlsSession, ()>>,
}

impl TlsSessionCache {
    pub fn new(per_host_session_capacity: usize) -> Self {
        TlsSessionCache {
            inner: Mutex::new(Inner {
                reverse: HashMap::new(),
                per_host_sessions: HashMap::new(),
            }),
            per_host_session_capacity,
        }
    }

    pub fn put(&self, key: String, session: TlsSession) {
        let mut inner = self.inner.lock().unwrap();

        let evicted = {
            let per_host_sessions =
                inner
                    .per_host_sessions
                    .entry(key.clone())
                    .or_insert_with(|| {
                        NonZeroUsize::new(self.per_host_session_capacity)
                            .map_or_else(LruCache::unbounded, LruCache::new)
                    });

            // Enforce per-key capacity limit by evicting the least recently used session
            let evicted = if per_host_sessions.len() >= self.per_host_session_capacity {
                per_host_sessions.pop_lru().map(|(s, _)| s)
            } else {
                None
            };

            per_host_sessions.put(session.clone(), ());
            evicted
        };

        if let Some(evicted_session) = evicted {
            inner.reverse.remove(&evicted_session);
        }
        inner.reverse.insert(session, key);
    }

    pub fn pop(&self, key: &str) -> Option<TlsSession> {
        let mut inner = self.inner.lock().unwrap();
        let session = {
            let per_host_sessions = inner.per_host_sessions.get_mut(key)?;
            per_host_sessions.peek_lru()?.0.clone()
        };

        // https://tools.ietf.org/html/rfc8446#appendix-C.4
        if session.protocol_version() == SslVersion::TLS1_3 {
            if let Some(key) = inner.reverse.remove(&session) {
                if let Entry::Occupied(mut entry) = inner.per_host_sessions.entry(key) {
                    entry.get_mut().pop(&session);
                    if entry.get().is_empty() {
                        entry.remove();
                    }
                }
            }
        }

        Some(session)
    }
}
