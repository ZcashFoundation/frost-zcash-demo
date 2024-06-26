use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

use uuid::Uuid;

use crate::{
    SerializedIdentifier, SerializedSignatureShare, SerializedSigningCommitments,
    SerializedSigningPackage,
};

use crate::SerializedRandomizer;

/// The current state of the server, and the required data for the state.
#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub enum SessionState {
    /// Waiting for participants to send their commitments.
    WaitingForCommitments {
        /// Commitments sent by participants so far, for each message being
        /// signed.
        commitments: HashMap<SerializedIdentifier, Vec<SerializedSigningCommitments>>,
    },
    /// Commitments have been sent by all participants; ready to be fetched by
    /// the coordinator. Waiting for coordinator to send the SigningPackage.
    CommitmentsReady {
        /// All commitments sent by participants, for each message being signed.
        commitments: HashMap<SerializedIdentifier, Vec<SerializedSigningCommitments>>,
    },
    /// SigningPackage ready to be fetched by participants. Waiting for
    /// participants to send their signature shares.
    WaitingForSignatureShares {
        /// Identifiers of the participants that sent commitments in the
        /// previous state.
        identifiers: HashSet<SerializedIdentifier>,
        /// SigningPackage sent by the coordinator to be sent to participants,
        /// for each message being signed.
        signing_package: Vec<SerializedSigningPackage>,
        /// Randomizer sent by coordinator to be sent to participants, for each
        /// message being signed. Can be empty if not being used.
        #[derivative(Debug = "ignore")]
        randomizer: Vec<SerializedRandomizer>,
        /// Auxiliary (optional) message. A context-specific data that is
        /// supposed to be interpreted by the participants.
        aux_msg: Vec<u8>,
        /// Signature shares sent by participants so far, for each message being
        /// signed.
        signature_shares: HashMap<SerializedIdentifier, Vec<SerializedSignatureShare>>,
    },
    /// SignatureShares have been sent by all participants; ready to be fetched
    /// by the coordinator.
    SignatureSharesReady {
        /// Signature shares sent by participants, for each message being signed.
        signature_shares: HashMap<SerializedIdentifier, Vec<SerializedSignatureShare>>,
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
#[derive(Debug)]
pub struct Session {
    /// The number of signers in the session.
    pub(crate) num_signers: u16,
    /// The set of identifiers for the session.
    // pub(crate) identifiers: BTreeSet<SerializedIdentifier>,
    /// The number of messages being simultaneously signed.
    pub(crate) message_count: u8,
    /// The session state.
    pub(crate) state: SessionState,
}

/// The global state of the server.
#[derive(Default, Debug)]
pub struct AppState {
    /// Mapping of signing sessions by UUID.
    pub(crate) sessions: HashMap<Uuid, Session>,
}

/// Type alias for the global state under a reference-counted RW mutex,
/// which allows reading and writing the state across different handlers.
pub type SharedState = Arc<RwLock<AppState>>;
