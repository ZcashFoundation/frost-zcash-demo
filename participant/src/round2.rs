#[cfg(feature = "redpallas")]
use frost::FieldError;
#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use frost::{
    keys::KeyPackage,
    round1::SigningNonces,
    round2::{self, SignatureShare},
    Error, SigningPackage,
};
use std::io::{BufRead, Write};

#[derive(Debug, Clone)]
pub struct Round2Config {
    pub signing_package: SigningPackage,
    #[cfg(feature = "redpallas")]
    pub randomizer: frost::round2::Randomizer,
}

// TODO: refactor to generate config
// TODO: handle errors
pub fn round_2_request_inputs(
    input: &mut impl BufRead,
    logger: &mut dyn Write,
) -> Result<Round2Config, Box<dyn std::error::Error>> {
    writeln!(logger, "=== Round 2 ===")?;

    writeln!(logger, "Enter the JSON-encoded SigningPackage:")?;

    let mut signing_package_json = String::new();

    input.read_line(&mut signing_package_json)?;

    // TODO: change to return a generic Error and use a better error
    let signing_package: SigningPackage = serde_json::from_str(signing_package_json.trim())
        .map_err(|_| Error::MalformedSigningKey)?;

    #[cfg(feature = "redpallas")]
    {
        writeln!(logger, "Enter the randomizer (hex string):")?;

        let mut json = String::new();

        input.read_line(&mut json).unwrap();

        let randomizer = frost::round2::Randomizer::deserialize(
            &hex::decode(json.trim())
                .map_err(|_| Error::FieldError(FieldError::MalformedScalar))?
                .try_into()
                .map_err(|_| Error::FieldError(FieldError::MalformedScalar))?,
        )?;
        Ok(Round2Config {
            signing_package,
            randomizer,
        })
    }

    #[cfg(not(feature = "redpallas"))]
    Ok(Round2Config { signing_package })
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
