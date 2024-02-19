use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use reddsa::frost::redpallas as frost;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateNewSessionArgs {
    pub num_signers: u16,
    pub message_count: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateNewSessionOutput {
    pub session_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSessionInfoArgs {
    pub session_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSessionInfoOutput {
    pub num_signers: u16,
    pub message_count: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendCommitmentsArgs {
    pub session_id: Uuid,
    pub identifier: frost::Identifier,
    pub commitments: Vec<frost::round1::SigningCommitments>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetCommitmentsArgs {
    pub session_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetCommitmentsOutput {
    pub commitments: Vec<BTreeMap<frost::Identifier, frost::round1::SigningCommitments>>,
}

#[derive(Serialize, Deserialize, derivative::Derivative)]
#[derivative(Debug)]
pub struct SendSigningPackageArgs {
    pub session_id: Uuid,
    pub signing_package: Vec<frost::SigningPackage>,
    pub aux_msg: Vec<u8>,
    #[derivative(Debug = "ignore")]
    pub randomizer: Vec<frost::round2::Randomizer>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSigningPackageArgs {
    pub session_id: Uuid,
}

#[derive(Serialize, Deserialize, derivative::Derivative)]
#[derivative(Debug)]
pub struct GetSigningPackageOutput {
    pub signing_package: Vec<frost::SigningPackage>,
    #[derivative(Debug = "ignore")]
    pub randomizer: Vec<frost::round2::Randomizer>,
    pub aux_msg: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendSignatureShareArgs {
    pub session_id: Uuid,
    pub identifier: frost::Identifier,
    pub signature_share: Vec<frost::round2::SignatureShare>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSignatureSharesArgs {
    pub session_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSignatureSharesOutput {
    pub signature_shares: Vec<BTreeMap<frost::Identifier, frost::round2::SignatureShare>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CloseSessionArgs {
    pub session_id: Uuid,
}
