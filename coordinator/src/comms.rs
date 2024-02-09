pub mod cli;
pub mod http;
pub mod socket;

#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use std::{
    collections::BTreeMap,
    error::Error,
    io::{BufRead, Write},
};

use async_trait::async_trait;

use frost::{
    keys::PublicKeyPackage,
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
    #[cfg(not(feature = "redpallas"))]
    SigningPackage(SigningPackage),
    #[cfg(feature = "redpallas")]
    SigningPackageAndRandomizer {
        signing_package: SigningPackage,
        randomizer: frost::round2::Randomizer,
    },
    SignatureShare(SignatureShare),
}

#[async_trait(?Send)]
pub trait Comms {
    async fn get_signing_commitments(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        pub_key_package: &PublicKeyPackage,
        num_of_participants: u16,
    ) -> Result<BTreeMap<Identifier, SigningCommitments>, Box<dyn Error>>;

    async fn get_signature_shares(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        signing_package: &SigningPackage,
        #[cfg(feature = "redpallas")] randomizer: frost::round2::Randomizer,
    ) -> Result<BTreeMap<Identifier, SignatureShare>, Box<dyn Error>>;
}
