use frost::{Error, Identifier, VerifyingKey};
use frost_ed25519 as frost;
use hex::FromHex;
use std::io::BufRead;

#[derive(Debug, PartialEq)]
pub struct Config {
    pub identifier: Identifier,
    pub public_key: [u8; 32],
    pub group_public_key: VerifyingKey,
}

pub trait Logger {
    fn log(&mut self, value: String);
}

pub fn request_inputs(input: &mut impl BufRead, logger: &mut dyn Logger) -> Result<Config, Error> {
    logger.log("Your identifier (this should be an integer between 1 and 65535):".to_string());

    let mut identifier_input = String::new();

    input.read_line(&mut identifier_input).unwrap();

    let identifier = identifier_input
        .trim()
        .parse::<u16>()
        .map_err(|_| Error::MalformedIdentifier)?;

    logger.log("Your public key:".to_string());

    let mut public_key_input = String::new();

    input.read_line(&mut public_key_input).unwrap();

    let public_key =
        <[u8; 32]>::from_hex(public_key_input.trim()).map_err(|_| Error::MalformedVerifyingKey)?;

    logger.log("The group public key:".to_string());

    let mut group_public_key_input = String::new();

    input.read_line(&mut group_public_key_input).unwrap();

    let group_public_key = VerifyingKey::from_hex(group_public_key_input.trim())
        .map_err(|_| Error::MalformedVerifyingKey)?; // TODO: Frost library needs to be updated with correct Error type

    logger.log("Your secret share:".to_string());

    Ok(Config {
        identifier: Identifier::try_from(identifier)?,
        public_key,
        group_public_key,
    })
}
