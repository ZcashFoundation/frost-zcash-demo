use std::{
    collections::{HashMap, HashSet, VecDeque},
    str::FromStr,
    sync::{Arc, RwLock},
};

use delay_map::{HashMapDelay, HashSetDelay};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};
use uuid::Uuid;

use crate::Msg;

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
    pub(crate) db: SqlitePool,
}

#[derive(Debug, Default)]
pub struct SessionState {
    /// Mapping of signing sessions by UUID.
    pub(crate) sessions: HashMap<Uuid, Session>,
    pub(crate) sessions_by_pubkey: HashMap<Vec<u8>, HashSet<Uuid>>,
}

impl AppState {
    pub async fn new(database: &str) -> Result<SharedState, Box<dyn std::error::Error>> {
        tracing::event!(tracing::Level::INFO, "opening database {}", database);
        let options = SqliteConnectOptions::from_str(database)?.create_if_missing(true);
        let db = SqlitePoolOptions::new().connect_with(options).await?;
        sqlx::migrate!().run(&db).await?;
        let state = Self {
            sessions: Default::default(),
            challenges: RwLock::new(HashSetDelay::new(std::time::Duration::from_secs(10))).into(),
            access_tokens: RwLock::new(HashMapDelay::new(std::time::Duration::from_secs(60 * 60)))
                .into(),
            db,
        };
        Ok(Arc::new(state))
    }
}

/// Type alias for the global state under a reference-counted RW mutex,
/// which allows reading and writing the state across different handlers.
pub type SharedState = Arc<AppState>;
