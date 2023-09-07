#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use frost::Error;
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
