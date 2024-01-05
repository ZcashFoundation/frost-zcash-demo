#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas::keys::PositiveY;

use crate::args::Args;
use crate::input::read_from_file_or_stdin;
use frost::{
    keys::{KeyPackage, SecretShare},
    round1::SigningCommitments,
    round1::SigningNonces,
    Error,
};
use rand::rngs::ThreadRng;
use std::io::{BufRead, Write};

// TODO: Rethink the types here. They're inconsistent with each other
#[derive(Debug, PartialEq)]
pub struct Round1Config {
    pub key_package: KeyPackage,
}

// TODO: refactor to generate config
pub async fn request_inputs(
    args: &Args,
    input: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<Round1Config, Box<dyn std::error::Error>> {
    writeln!(logger, "Your JSON-encoded secret share or key package:")?;

    let secret_share = read_from_file_or_stdin(input, logger, "key package", &args.key_package)?;

    let key_package = if let Ok(secret_share) = serde_json::from_str::<SecretShare>(&secret_share) {
        KeyPackage::try_from(secret_share)?
    } else {
        // TODO: Improve error
        serde_json::from_str::<KeyPackage>(&secret_share).map_err(|_| Error::InvalidSecretShare)?
    };

    #[cfg(feature = "redpallas")]
    let key_package = key_package.into_positive_y();

    Ok(Round1Config { key_package })
}

pub fn generate_nonces_and_commitments(
    key_package: &KeyPackage,
    rng: &mut ThreadRng,
) -> (SigningNonces, SigningCommitments) {
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), rng);

    // TODO: Store nonces

    (nonces, commitments)
}

pub fn print_values(
    commitments: SigningCommitments,
    logger: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(logger, "=== Round 1 ===")?;
    writeln!(logger, "SigningNonces were generated and stored in memory")?;
    writeln!(
        logger,
        "SigningCommitments:\n{}",
        serde_json::to_string(&commitments).unwrap(),
    )?;
    writeln!(logger, "=== Round 1 Completed ===")?;
    writeln!(
        logger,
        "Please send your SigningCommitments to the coordinator"
    )?;

    Ok(())
}
