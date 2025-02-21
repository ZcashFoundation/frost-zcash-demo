use frost_core::{Ciphersuite, SigningPackage};
use frost_rerandomized::Randomizer;
use serde::{Deserialize, Serialize};
pub use uuid::Uuid;

/// The maximum size of a message.
pub const MAX_MSG_SIZE: usize = 65535;

#[derive(Debug, Serialize, Deserialize)]
pub struct Error {
    pub code: usize,
    pub msg: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeArgs {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeOutput {
    pub challenge: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyLoginArgs {
    pub challenge: Uuid,
    pub pubkey: PublicKey,
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyLoginOutput {
    pub access_token: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginOutput {
    pub access_token: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginArgs {
    pub username: String,
    pub password: String,
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

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
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
