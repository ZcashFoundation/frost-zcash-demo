pub mod cli;
pub mod socket;

use async_trait::async_trait;

#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use std::{
    error::Error,
    io::{BufRead, Write},
};

use frost::{
    round1::SigningCommitments,
    round2::SignatureShare,
    serde::{self, Deserialize, Serialize},
    Identifier, SigningPackage,
};

#[derive(Serialize, Deserialize)]
#[serde(crate = "self::serde")]
#[allow(clippy::large_enum_variant)]
pub enum Message {
    IdentifiedCommitments {
        identifier: Identifier,
        commitments: SigningCommitments,
    },
    SigningPackage(SigningPackage),
    SignatureShare(SignatureShare),
}

#[async_trait(?Send)]
pub trait Comms {
    async fn get_signing_package(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        commitments: SigningCommitments,
        identifier: Identifier,
    ) -> Result<SigningPackage, Box<dyn Error>>;

    async fn send_signature_share(
        &mut self,
        signature_share: SignatureShare,
    ) -> Result<(), Box<dyn Error>>;
}
