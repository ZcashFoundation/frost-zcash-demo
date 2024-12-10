use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, RwLock},
};

use delay_map::{HashMapDelay, HashSetDelay};
use uuid::Uuid;

use crate::Msg;

/// How long a challenge can be replied to.
const CHALLENGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How long an acesss token lasts.
const ACCESS_TOKEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60 * 60);

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
    pub(crate) sessions: Arc<RwLock<SessionState>>,
    pub(crate) challenges: Arc<RwLock<HashSetDelay<Uuid>>>,
    pub(crate) access_tokens: Arc<RwLock<HashMapDelay<Uuid, Vec<u8>>>>,
}

#[derive(Debug, Default)]
pub struct SessionState {
    /// Mapping of signing sessions by UUID.
    pub(crate) sessions: HashMap<Uuid, Session>,
    pub(crate) sessions_by_pubkey: HashMap<Vec<u8>, HashSet<Uuid>>,
}

impl AppState {
    pub async fn new() -> Result<SharedState, Box<dyn std::error::Error>> {
        let state = Self {
            sessions: Default::default(),
            challenges: RwLock::new(HashSetDelay::new(CHALLENGE_TIMEOUT)).into(),
            access_tokens: RwLock::new(HashMapDelay::new(ACCESS_TOKEN_TIMEOUT)).into(),
        };
        Ok(Arc::new(state))
    }
}

/// Type alias for the global state under a reference-counted pointer.
pub type SharedState = Arc<AppState>;
