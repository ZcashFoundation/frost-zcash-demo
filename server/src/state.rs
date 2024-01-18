use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, RwLock},
};

use uuid::Uuid;

use reddsa::frost::redpallas as frost;

pub enum SessionState {
    WaitingForCommitments {
        commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
    },
    CommitmentsReady {
        commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
    },
    WaitingForSignatureShares {
        signing_package: frost::SigningPackage,
        randomizer: frost::round2::Randomizer,
        signature_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
    },
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

pub struct Session {
    pub(crate) identifiers: BTreeSet<frost::Identifier>,
    pub(crate) state: SessionState,
}

#[derive(Default)]
pub struct AppState {
    pub(crate) sessions: HashMap<Uuid, Session>,
}

pub type SharedState = Arc<RwLock<AppState>>;
