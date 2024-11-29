use std::{
    collections::{HashMap, HashSet, VecDeque},
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::Duration,
};

use delay_map::{HashMapDelay, HashSetDelay};
use futures::{Stream, StreamExt as _};
use uuid::Uuid;

use crate::Msg;

/// How long a session stays open.
const SESSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60 * 60 * 24);
/// How long a challenge can be replied to.
const CHALLENGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How long an acesss token lasts.
const ACCESS_TOKEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Helper struct that allows calling `next()` on a `Stream` behind a `RwLock`
/// (namely a `HashMapDelay` or `HashSetDelay` in our case) without locking
/// the `RwLock` while waiting.
// From https://users.rust-lang.org/t/how-do-i-poll-a-stream-behind-a-rwlock/121787/2
struct RwLockStream<'a, T>(pub &'a RwLock<T>);

impl<'a, T: Stream + Unpin> Stream for RwLockStream<'a, T> {
    type Item = T::Item;
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<<Self as Stream>::Item>> {
        self.0.write().unwrap().poll_next_unpin(cx)
    }
}

/// A particular signing session.
#[derive(Debug)]
pub struct Session {
    /// The public keys of the participants
    pub(crate) pubkeys: Vec<Vec<u8>>,
    /// The public key of the coordinator
    pub(crate) coordinator_pubkey: Vec<u8>,
    /// The number of signers in the session.
    pub(crate) num_signers: u16,
    /// The set of identifiers for the session.
    // pub(crate) identifiers: BTreeSet<SerializedIdentifier>,
    /// The number of messages being simultaneously signed.
    pub(crate) message_count: u8,
    /// The message queue.
    pub(crate) queue: HashMap<Vec<u8>, VecDeque<Msg>>,
}

/// The global state of the server.
#[derive(Debug)]
pub struct AppState {
    pub(crate) sessions: SessionState,
    pub(crate) challenges: Arc<RwLock<HashSetDelay<Uuid>>>,
    pub(crate) access_tokens: Arc<RwLock<HashMapDelay<Uuid, Vec<u8>>>>,
}

#[derive(Debug, Default)]
pub struct SessionState {
    /// Mapping of signing sessions by UUID.
    pub(crate) sessions: Arc<RwLock<HashMapDelay<Uuid, Session>>>,
    pub(crate) sessions_by_pubkey: Arc<RwLock<HashMap<Vec<u8>, HashSet<Uuid>>>>,
}

impl SessionState {
    /// Create a new SessionState
    pub fn new(timeout: Duration) -> Self {
        Self {
            sessions: RwLock::new(HashMapDelay::new(timeout)).into(),
            sessions_by_pubkey: Default::default(),
        }
    }
}

impl AppState {
    pub async fn new() -> Result<SharedState, Box<dyn std::error::Error>> {
        let state = Arc::new(Self {
            sessions: SessionState::new(SESSION_TIMEOUT),
            challenges: RwLock::new(HashSetDelay::new(CHALLENGE_TIMEOUT)).into(),
            access_tokens: RwLock::new(HashMapDelay::new(ACCESS_TOKEN_TIMEOUT)).into(),
        });

        // In order to effectively removed timed out entries, we need to
        // repeatedly call `next()` on them.
        // These tasks will just run forever and will stop when the server stops.

        let state_clone = state.clone();
        tokio::task::spawn(async move {
            loop {
                match RwLockStream(&state_clone.sessions.sessions).next().await {
                    Some(Ok((uuid, session))) => {
                        tracing::debug!("session {} timed out", uuid);
                        let mut sessions_by_pubkey =
                            state_clone.sessions.sessions_by_pubkey.write().unwrap();
                        for pubkey in session.pubkeys {
                            if let Some(sessions) = sessions_by_pubkey.get_mut(&pubkey) {
                                sessions.remove(&uuid);
                            }
                        }
                    }
                    _ => {
                        // Annoyingly, if the map is empty, it returns
                        // immediately instead of waiting for an entry to be
                        // inserted and waiting for that to timeout. To avoid a
                        // busy loop when the map is empty, we sleep for a bit.
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
        // TODO: we could refactor these two loops with a generic function
        // but it's just simpler to do this directly currently
        let state_clone = state.clone();
        tokio::task::spawn(async move {
            loop {
                match RwLockStream(&state_clone.challenges).next().await {
                    Some(Ok(challenge)) => {
                        tracing::debug!("challenge {} timed out", challenge);
                    }
                    _ => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
        let state_clone = state.clone();
        tokio::task::spawn(async move {
            loop {
                match RwLockStream(&state_clone.access_tokens).next().await {
                    Some(Ok((access_token, _pubkey))) => {
                        tracing::debug!("access_token {} timed out", access_token);
                    }
                    _ => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
        Ok(state)
    }
}

/// Type alias for the global state under a reference-counted pointer.
pub type SharedState = Arc<AppState>;
