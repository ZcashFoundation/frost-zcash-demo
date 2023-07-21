use crate::Logger;
use frost::{
    keys::{KeyPackage, SecretShare},
    round1::SigningCommitments,
    Error,
};
use frost_ed25519 as frost;
use std::io::BufRead;

// TODO: Rethink the types here. They're inconsistent with each other
#[derive(Debug, PartialEq)]
pub struct Round1Config {
    pub secret_share: SecretShare,
}

// pub trait Logger {
//     fn log(&mut self, value: String);
// }

// TODO: refactor to generate config
pub fn request_inputs(
    input: &mut impl BufRead,
    logger: &mut dyn Logger,
) -> Result<Round1Config, Error> {
    logger.log("Your JSON-encoded secret share:".to_string());

    let mut secret_share_json = String::new();

    input.read_line(&mut secret_share_json).unwrap();

    let secret_share: SecretShare =
        serde_json::from_str(&secret_share_json).map_err(|_| Error::InvalidSecretShare)?;

    Ok(Round1Config { secret_share })
}

pub fn generate_key_package(config: &Round1Config) -> Result<KeyPackage, Error> {
    let key_package = KeyPackage::try_from(config.secret_share.clone())?;

    Ok(key_package)
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
