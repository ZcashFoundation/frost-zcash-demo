#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use crate::comms::Comms;
use frost::{
    keys::KeyPackage,
    round1::{SigningCommitments, SigningNonces},
    round2::{self, SignatureShare},
    Error, Identifier, SigningPackage,
};
use std::io::{BufRead, Write};

#[derive(Clone)]
pub struct Round2Config {
    pub signing_package: SigningPackage,
    #[cfg(feature = "redpallas")]
    pub randomizer: frost::round2::Randomizer,
}

// TODO: refactor to generate config
// TODO: handle errors
pub async fn round_2_request_inputs(
    comms: &mut dyn Comms,
    input: &mut impl BufRead,
    logger: &mut dyn Write,
    commitments: SigningCommitments,
    identifier: Identifier,
) -> Result<Round2Config, Box<dyn std::error::Error>> {
    writeln!(logger, "=== Round 2 ===")?;

    let r = comms
        .get_signing_package(input, logger, commitments, identifier)
        .await?;

    #[cfg(feature = "redpallas")]
    {
        Ok(Round2Config {
            signing_package: r.0,
            randomizer: r.1,
        })
    }

    #[cfg(not(feature = "redpallas"))]
    Ok(Round2Config { signing_package: r })
}

pub fn generate_signature(
    config: Round2Config,
    key_package: &KeyPackage,
    signing_nonces: &SigningNonces,
) -> Result<SignatureShare, Error> {
    let signing_package = config.signing_package;
    #[cfg(not(feature = "redpallas"))]
    let signature = round2::sign(&signing_package, signing_nonces, key_package)?;

    #[cfg(feature = "redpallas")]
    let signature = round2::sign(
        &signing_package,
        signing_nonces,
        key_package,
        config.randomizer,
    )?;
    Ok(signature)
}

pub fn print_values_round_2(
    signature: SignatureShare,
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
