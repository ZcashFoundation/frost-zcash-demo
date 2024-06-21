use frost_core::{self as frost, Ciphersuite};

use frost::{
    keys::dkg::{round1, round2},
    Error, Identifier,
};

use eyre::eyre;

use std::io::{BufRead, Write};

#[derive(Debug, PartialEq, Clone)]
pub struct Config<C: Ciphersuite> {
    pub min_signers: u16,
    pub max_signers: u16,
    pub identifier: Identifier<C>,
}

fn validate_inputs<C: Ciphersuite>(config: &Config<C>) -> Result<(), Error<C>> {
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

pub fn request_inputs<C: Ciphersuite + 'static>(
    input: &mut impl BufRead,
    logger: &mut dyn Write,
) -> Result<Config<C>, Box<dyn std::error::Error>> {
    writeln!(logger, "The minimum number of signers: (2 or more)")?;

    let mut min = String::new();
    input.read_line(&mut min)?;

    let min_signers = min
        .trim()
        .parse::<u16>()
        .map_err(|_| Error::<C>::InvalidMinSigners)?;

    writeln!(logger, "The maximum number of signers:")?;

    let mut max = String::new();
    input.read_line(&mut max)?;
    let max_signers = max
        .trim()
        .parse::<u16>()
        .map_err(|_| Error::<C>::InvalidMaxSigners)?;

    writeln!(
        logger,
        "Your identifier (this should be an integer between 1 and 65535):"
    )?;

    let mut identifier_input = String::new();

    input.read_line(&mut identifier_input)?;

    let u16_identifier = identifier_input
        .trim()
        .parse::<u16>()
        .map_err(|_| Error::<C>::MalformedIdentifier)?;
    let identifier = u16_identifier.try_into()?;

    let config = Config {
        min_signers,
        max_signers,
        identifier,
    };

    validate_inputs(&config)?;

    Ok(config)
}

pub fn read_identifier<C: Ciphersuite + 'static>(
    input: &mut impl BufRead,
) -> Result<Identifier<C>, Box<dyn std::error::Error>> {
    let mut identifier_input = String::new();
    input.read_line(&mut identifier_input)?;
    let bytes = hex::decode(identifier_input.trim())?;
    let serialization = bytes.try_into().map_err(|_| eyre!("Invalid Identifier"))?;
    let identifier = Identifier::<C>::deserialize(&serialization)?;
    Ok(identifier)
}

pub fn read_round1_package<C: Ciphersuite + 'static>(
    input: &mut impl BufRead,
    logger: &mut dyn Write,
) -> Result<(Identifier<C>, round1::Package<C>), Box<dyn std::error::Error>> {
    writeln!(logger, "The sender's identifier (hex string):")?;

    let identifier = read_identifier::<C>(input)?;

    writeln!(logger, "Their JSON-encoded Round 1 Package:")?;

    let mut package_input = String::new();
    input.read_line(&mut package_input)?;
    let round1_package = serde_json::from_str(&package_input)?;

    Ok((identifier, round1_package))
}

pub fn read_round2_package<C: Ciphersuite + 'static>(
    input: &mut impl BufRead,
    logger: &mut dyn Write,
) -> Result<(Identifier<C>, round2::Package<C>), Box<dyn std::error::Error>> {
    writeln!(logger, "The sender's identifier (hex string):")?;

    let identifier = read_identifier::<C>(input)?;

    writeln!(logger, "Their JSON-encoded Round 2 Package:")?;

    let mut package_input = String::new();
    input.read_line(&mut package_input)?;
    let round2_package = serde_json::from_str(&package_input)?;

    Ok((identifier, round2_package))
}
