use frost_core::{self as frost, Ciphersuite};

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
pub struct Round1Config<C: Ciphersuite> {
    pub key_package: KeyPackage<C>,
}

// TODO: refactor to generate config
pub async fn request_inputs<C: Ciphersuite + 'static>(
    args: &Args,
    input: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<Round1Config<C>, Box<dyn std::error::Error>> {
    writeln!(logger, "Your JSON-encoded secret share or key package:")?;

    let secret_share = read_from_file_or_stdin(input, logger, "key package", &args.key_package)?;

    let key_package =
        if let Ok(secret_share) = serde_json::from_str::<SecretShare<C>>(&secret_share) {
            KeyPackage::try_from(secret_share)?
        } else {
            // TODO: Improve error
            serde_json::from_str::<KeyPackage<C>>(&secret_share)
                .map_err(|_| Error::<C>::InvalidSecretShare)?
        };

    Ok(Round1Config { key_package })
}

pub fn print_values<C: Ciphersuite>(
    commitments: SigningCommitments<C>,
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

pub fn generate_nonces_and_commitments<C: Ciphersuite>(
    key_package: &KeyPackage<C>,
    rng: &mut ThreadRng,
) -> (SigningNonces<C>, SigningCommitments<C>) {
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), rng);

    // TODO: Store nonces

    (nonces, commitments)
}
