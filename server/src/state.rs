use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, RwLock},
};

use uuid::Uuid;

use reddsa::frost::redpallas as frost;

/// The current state of the server, and the required data for the state.
pub enum SessionState {
    /// Waiting for participants to send their commitments.
    WaitingForCommitments {
        /// Commitments sent by participants so far.
        commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
    },
    /// Commitments have been sent by all participants; ready to be fetched by
    /// the coordinator. Waiting for coordinator to send the SigningPackage.
    CommitmentsReady {
        /// All commitments sent by participants.
        commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
    },
    /// SigningPackage ready to be fetched by participants. Waiting for
    /// participants to send their signature shares.
    WaitingForSignatureShares {
        /// SigningPackage sent by the coordinator to be sent to participants.
        signing_package: frost::SigningPackage,
        /// Randomizer sent by coordinator to be sent to participants
        /// (Rerandomized FROST only. TODO: make it optional?)
        randomizer: frost::round2::Randomizer,
        /// Signature shares sent by participants so far.
        signature_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
    },
    /// SignatureShares have been sent by all participants; ready to be fetched
    /// by the coordinator.
    SignatureSharesReady {
        signature_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
    },
}

impl Default for SessionState {
    fn default() -> Self {
        SessionState::WaitingForCommitments {
            commitments: Default::default(),
        }
    }
}

/// A particular signing session.
pub struct Session {
    /// The set of identifiers for the session.
    pub(crate) identifiers: BTreeSet<frost::Identifier>,
    /// The session state.
    pub(crate) state: SessionState,
}

/// The global state of the server.
#[derive(Default)]
pub struct AppState {
    /// Mapping of signing sessions by UUID.
    pub(crate) sessions: HashMap<Uuid, Session>,
}

/// Type alias for the global state under a reference-counted RW mutex,
/// which allows reading and writing the state across different handlers.
pub type SharedState = Arc<RwLock<AppState>>;
