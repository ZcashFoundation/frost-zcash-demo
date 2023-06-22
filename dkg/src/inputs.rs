use frost::{
    keys::dkg::{round1, round2},
    Error, Identifier,
};
use frost_ed25519 as frost;
use std::io::BufRead;

#[derive(Debug, PartialEq, Clone)]
pub struct Config {
    pub min_signers: u16,
    pub max_signers: u16,
    pub identifier: Identifier,
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

pub fn request_inputs(input: &mut impl BufRead) -> Result<Config, Error> {
    println!("The minimum number of signers: (2 or more)");

    let mut min = String::new();
    input.read_line(&mut min).unwrap();

    let min_signers = min
        .trim()
        .parse::<u16>()
        .map_err(|_| Error::InvalidMinSigners)?;

    println!("The maximum number of signers: ");

    let mut max = String::new();
    input.read_line(&mut max).unwrap();
    let max_signers = max
        .trim()
        .parse::<u16>()
        .map_err(|_| Error::InvalidMaxSigners)?;

    println!("Your identifier (this should be an integer between 1 and 65535):");

    let mut identifier_input = String::new();

    input.read_line(&mut identifier_input).unwrap();

    let u16_identifier = identifier_input
        .trim()
        .parse::<u16>()
        .map_err(|_| Error::MalformedIdentifier)?;
    let identifier = u16_identifier.try_into()?;

    let config = Config {
        min_signers,
        max_signers,
        identifier,
    };

    validate_inputs(&config)?;

    Ok(config)
}

pub fn read_round1_package(
    input: &mut impl BufRead,
) -> Result<(Identifier, round1::Package), Error> {
    println!("The sender's identifier (hex string):");

    let mut identifier_input = String::new();
    input.read_line(&mut identifier_input).unwrap();
    let identifier = Identifier::deserialize(
        &hex::decode(identifier_input.trim())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();

    println!("Their JSON-encoded Round 1 Package:");

    let mut package_input = String::new();
    input.read_line(&mut package_input).unwrap();
    let round1_package = serde_json::from_str(&package_input).unwrap();

    Ok((identifier, round1_package))
}

pub fn read_round2_package(
    input: &mut impl BufRead,
) -> Result<(Identifier, round2::Package), Error> {
    println!("The participant identifier (this should be an integer between 1 and 65535):");

    let mut identifier_input = String::new();
    input.read_line(&mut identifier_input).unwrap();
    let identifier = Identifier::deserialize(
        &hex::decode(identifier_input.trim())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();

    println!("Their JSON-encoded Round 1 Package:");

    let mut package_input = String::new();
    input.read_line(&mut package_input).unwrap();
    let round2_package = serde_json::from_str(&package_input).unwrap();

    Ok((identifier, round2_package))
}
