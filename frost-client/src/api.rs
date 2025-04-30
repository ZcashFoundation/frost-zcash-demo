//! Types for the FROST server API.

use frost_core::{Ciphersuite, SigningPackage};
use frost_rerandomized::Randomizer;
use serde::{Deserialize, Serialize};
use thiserror::Error;
pub use uuid::Uuid;
use zeroize::Zeroize;

/// The maximum size of a message.
pub const MAX_MSG_SIZE: usize = 65535;

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeOutput {
    pub challenge: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginArgs {
    pub challenge: Uuid,
    pub pubkey: PublicKey,
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginOutput {
    pub access_token: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateNewSessionArgs {
    pub pubkeys: Vec<PublicKey>,
    pub message_count: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateNewSessionOutput {
    pub session_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListSessionsOutput {
    pub session_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetSessionInfoArgs {
    pub session_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetSessionInfoOutput {
    pub message_count: u8,
    pub pubkeys: Vec<PublicKey>,
    pub coordinator_pubkey: PublicKey,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Zeroize)]
#[serde(transparent)]
pub struct PublicKey(
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub Vec<u8>,
);

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PublicKey")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendArgs {
    pub session_id: Uuid,
    pub recipients: Vec<PublicKey>,
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub msg: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Msg {
    pub sender: PublicKey,
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub msg: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiveArgs {
    pub session_id: Uuid,
    pub as_coordinator: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiveOutput {
    pub msgs: Vec<Msg>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloseSessionArgs {
    pub session_id: Uuid,
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct SendSigningPackageArgs<C: Ciphersuite> {
    pub signing_package: Vec<SigningPackage<C>>,
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub aux_msg: Vec<u8>,
    pub randomizer: Vec<Randomizer<C>>,
}

/// An error. Wraps a StatusCode which is returned by the server when the
/// error happens during a API call, and a generic eyre::Report.
#[derive(Debug, Error, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", content = "err")]
pub enum Error {
    #[error("invalid or missing argument: {0}")]
    InvalidArgument(String),
    #[error("client did not provide proper authorization credentials")]
    Unauthorized,
    #[error("session was not found")]
    SessionNotFound,
    #[error("user is not the coordinator")]
    NotCoordinator,
    #[error("user is not part of the given session")]
    NotInSession,
    #[serde(other)]
    #[error("unknown error")]
    Unknown,
}

// These make it easier to clients to tell which error happened.
pub const INVALID_ARGUMENT: usize = 1;
pub const UNAUTHORIZED: usize = 2;
pub const SESSION_NOT_FOUND: usize = 3;
pub const NOT_COORDINATOR: usize = 4;
pub const NOT_IN_SESSION: usize = 5;
pub const UNKNOWN: usize = 255;

impl Error {
    pub fn error_code(&self) -> usize {
        match &self {
            Error::InvalidArgument(_) => INVALID_ARGUMENT,
            Error::Unauthorized => UNAUTHORIZED,
            Error::SessionNotFound => SESSION_NOT_FOUND,
            Error::NotCoordinator => NOT_COORDINATOR,
            Error::NotInSession => NOT_IN_SESSION,
            Error::Unknown => UNKNOWN,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LowError {
    pub code: usize,
    pub msg: String,
    pub error: Error,
}

impl From<Error> for LowError {
    fn from(err: Error) -> Self {
        LowError {
            code: err.error_code(),
            msg: err.to_string(),
            error: err,
        }
    }
}

impl From<LowError> for Error {
    fn from(err: LowError) -> Self {
        err.error
    }
}
