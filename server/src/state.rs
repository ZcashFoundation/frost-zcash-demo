use std::{
    collections::{HashMap, HashSet, VecDeque},
    str::FromStr,
    sync::{Arc, RwLock},
};

use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};
use uuid::Uuid;

use crate::Msg;

/// A particular signing session.
#[derive(Debug)]
pub struct Session {
    /// The usernames of the participants
    pub(crate) usernames: Vec<String>,
    /// The username of the coordinator
    pub(crate) coordinator: String,
    /// The number of signers in the session.
    pub(crate) num_signers: u16,
    /// The set of identifiers for the session.
    // pub(crate) identifiers: BTreeSet<SerializedIdentifier>,
    /// The number of messages being simultaneously signed.
    pub(crate) message_count: u8,
    /// The message queue.
    pub(crate) queue: HashMap<String, VecDeque<Msg>>,
}

/// The global state of the server.
#[derive(Debug)]
pub struct AppState {
    /// Mapping of signing sessions by UUID.
    pub(crate) sessions: HashMap<Uuid, Session>,
    pub(crate) sessions_by_username: HashMap<String, HashSet<Uuid>>,
    pub(crate) db: SqlitePool,
}

impl AppState {
    pub async fn new(database: &str) -> Result<SharedState, Box<dyn std::error::Error>> {
        tracing::event!(tracing::Level::INFO, "opening database {}", database);
        let options = SqliteConnectOptions::from_str(database)?.create_if_missing(true);
        let db = SqlitePoolOptions::new().connect_with(options).await?;
        sqlx::migrate!().run(&db).await?;
        let state = Self {
            sessions: Default::default(),
            sessions_by_username: Default::default(),
            db,
        };
        Ok(Arc::new(RwLock::new(state)))
    }
}

/// Type alias for the global state under a reference-counted RW mutex,
/// which allows reading and writing the state across different handlers.
pub type SharedState = Arc<RwLock<AppState>>;
