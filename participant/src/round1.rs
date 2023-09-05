#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas::keys::PositiveY;

use crate::Logger;
use frost::{
    keys::{KeyPackage, SecretShare},
    round1::SigningCommitments,
    Error,
};
use std::io::BufRead;

// TODO: Rethink the types here. They're inconsistent with each other
#[derive(Debug, PartialEq)]
pub struct Round1Config {
    pub key_package: KeyPackage,
}

// TODO: refactor to generate config
pub fn request_inputs(
    input: &mut impl BufRead,
    logger: &mut dyn Logger,
) -> Result<Round1Config, Error> {
    logger.log("Your JSON-encoded secret share or key package:".to_string());

    let mut json = String::new();

    input.read_line(&mut json).unwrap();

    let key_package = if let Ok(secret_share) = serde_json::from_str::<SecretShare>(&json) {
        KeyPackage::try_from(secret_share)?
    } else {
        // TODO: Improve error
        serde_json::from_str::<KeyPackage>(&json).map_err(|_| Error::InvalidSecretShare)?
    };

    #[cfg(feature = "redpallas")]
    let key_package = key_package.into_positive_y();

    Ok(Round1Config { key_package })
}

// The nonces are printed out here for demo purposes only. The hiding and binding nonces are SECRET and not to be shared.
pub fn print_values(commitments: SigningCommitments, logger: &mut dyn Logger) {
    logger.log("=== Round 1 ===".to_string());
    logger.log("SigningNonces were generated and stored in memory".to_string());
    logger.log(format!(
        "SigningCommitments:\n{}",
        serde_json::to_string(&commitments).unwrap(),
    ));
    logger.log("=== Round 1 Completed ===".to_string());
    logger.log("Please send your SigningCommitments to the coordinator".to_string());
}
