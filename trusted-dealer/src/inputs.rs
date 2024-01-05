#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use frost::keys::{PublicKeyPackage, SecretShare};
use frost::Error;
use frost::Identifier;
use itertools::Itertools;
use std::collections::BTreeMap;
use std::io::{BufRead, Write};

#[derive(Debug, PartialEq, Clone)]
pub struct Config {
    pub min_signers: u16,
    pub max_signers: u16,
    pub secret: Vec<u8>,
}

fn validate_inputs(config: &Config) -> Result<(), Error> {
    if config.min_signers < 2 {
        return Err(Error::InvalidMinSigners);
    }

    if config.max_signers < 2 {
        return Err(Error::InvalidMaxSigners);
    }

    if config.min_signers > config.max_signers {
        return Err(Error::InvalidMinSigners);
    }

    Ok(())
}

pub fn request_inputs(
    input: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<Config, Box<dyn std::error::Error>> {
    writeln!(logger, "The minimum number of signers: (2 or more)")?;

    let mut min = String::new();
    input.read_line(&mut min)?;

    let min_signers = min
        .trim()
        .parse::<u16>()
        .map_err(|_| Error::InvalidMinSigners)?;

    writeln!(logger, "The maximum number of signers: ")?;

    let mut max = String::new();
    input.read_line(&mut max)?;
    let max_signers = max
        .trim()
        .parse::<u16>()
        .map_err(|_| Error::InvalidMaxSigners)?;

    writeln!(
        logger,
        "Secret key (press enter to randomly generate a fresh one): "
    )?;

    let mut secret_input = String::new();
    input.read_line(&mut secret_input)?;
    let secret = hex::decode(secret_input.trim()).map_err(|_| Error::MalformedSigningKey)?;

    let config = Config {
        min_signers,
        max_signers,
        secret,
    };

    validate_inputs(&config)?;

    Ok(config)
}

pub fn print_values(
    keys: &BTreeMap<Identifier, SecretShare>,
    pubkeys: &PublicKeyPackage,
    logger: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(
        logger,
        "Public key package:\n{}",
        serde_json::to_string(pubkeys).unwrap()
    )?;

    for (k, v) in keys.iter().sorted_by_key(|x| x.0) {
        writeln!(logger, "Participant: {}", hex::encode(k.serialize()))?;
        writeln!(
            logger,
            "Secret share:\n{}",
            serde_json::to_string(v).unwrap()
        )?;
    }

    Ok(())
}
