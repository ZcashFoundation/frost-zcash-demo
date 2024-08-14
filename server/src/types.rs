use frost_core::{
    round1::SigningCommitments, round2::SignatureShare, Ciphersuite, Identifier, SigningPackage,
};
use frost_rerandomized::Randomizer;
use serde::{Deserialize, Serialize};
pub use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterArgs {
    pub username: String,
    pub password: String,
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub pubkey: Vec<u8>,
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
    pub usernames: Vec<String>,
    pub num_signers: u16,
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
    pub num_signers: u16,
    pub message_count: u8,
    pub usernames: Vec<String>,
    pub coordinator: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendArgs {
    pub session_id: Uuid,
    pub recipients: Vec<String>,
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub msg: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Msg {
    pub sender: String,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct SendCommitmentsArgs<C: Ciphersuite> {
    pub identifier: Identifier<C>,
    pub commitments: Vec<SigningCommitments<C>>,
}

#[derive(Serialize, Deserialize, derivative::Derivative)]
#[derivative(Debug)]
#[serde(bound = "C: Ciphersuite")]
pub struct SendSigningPackageArgs<C: Ciphersuite> {
    pub signing_package: Vec<SigningPackage<C>>,
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub aux_msg: Vec<u8>,
    #[derivative(Debug = "ignore")]
    pub randomizer: Vec<Randomizer<C>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct SendSignatureSharesArgs<C: Ciphersuite> {
    pub identifier: Identifier<C>,
    pub signature_share: Vec<SignatureShare<C>>,
}
