use frost_core::{self as frost, Ciphersuite};

use crate::comms::Comms;
use frost::{
    keys::KeyPackage,
    round1::{SigningCommitments, SigningNonces},
    round2::{self, SignatureShare},
    Error, Identifier, SigningPackage,
};
use std::io::{BufRead, Write};

#[derive(Clone)]
pub struct Round2Config<C: Ciphersuite> {
    pub signing_package: SigningPackage<C>,
    pub randomizer: Option<frost_rerandomized::Randomizer<C>>,
}

// TODO: refactor to generate config
// TODO: handle errors
pub async fn round_2_request_inputs<C: Ciphersuite>(
    comms: &mut dyn Comms<C>,
    input: &mut impl BufRead,
    logger: &mut dyn Write,
    commitments: SigningCommitments<C>,
    identifier: Identifier<C>,
    rerandomized: bool,
) -> Result<Round2Config<C>, Box<dyn std::error::Error>> {
    writeln!(logger, "=== Round 2 ===")?;

    let r = comms
        .get_signing_package(input, logger, commitments, identifier, rerandomized)
        .await?;

    Ok(Round2Config {
        signing_package: r.0,
        randomizer: r.1,
    })
}

pub fn generate_signature<C: frost_rerandomized::RandomizedCiphersuite>(
    config: Round2Config<C>,
    key_package: &KeyPackage<C>,
    signing_nonces: &SigningNonces<C>,
) -> Result<SignatureShare<C>, Error<C>> {
    let signing_package = config.signing_package;

    let signature = if let Some(randomizer) = config.randomizer {
        frost_rerandomized::sign::<C>(&signing_package, signing_nonces, key_package, randomizer)?
    } else {
        round2::sign(&signing_package, signing_nonces, key_package)?
    };
    Ok(signature)
}

pub fn print_values_round_2<C: Ciphersuite>(
    signature: SignatureShare<C>,
    logger: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(logger, "Please send the following to the Coordinator")?;
    writeln!(
        logger,
        "SignatureShare:\n{}",
        serde_json::to_string(&signature).unwrap()
    )?;
    writeln!(logger, "=== End of Round 2 ===")?;

    Ok(())
}
