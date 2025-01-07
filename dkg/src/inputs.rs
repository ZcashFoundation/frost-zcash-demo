use frost_core::{self as frost, Ciphersuite};

use frost::{
    keys::dkg::{round1, round2},
    Error, Identifier,
};

use tokio::io::AsyncBufReadExt as BufReadExt;
use tokio::io::AsyncWriteExt as WriteExt;
use tokio::io::{AsyncBufRead as BufRead, AsyncWrite as Write};

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

pub async fn request_inputs<C: Ciphersuite + 'static>(
    input: &mut (impl BufRead + Send + Sync + Unpin),
    logger: &mut (dyn Write + Send + Sync + Unpin),
) -> Result<Config<C>, Box<dyn std::error::Error>> {
    logger
        .write_all(b"The minimum number of signers: (2 or more)\n")
        .await?;

    let mut min = String::new();
    input.read_line(&mut min).await?;

    let min_signers = min
        .trim()
        .parse::<u16>()
        .map_err(|_| Error::<C>::InvalidMinSigners)?;

    logger
        .write_all(b"The maximum number of signers:\n")
        .await?;

    let mut max = String::new();
    input.read_line(&mut max).await?;
    let max_signers = max
        .trim()
        .parse::<u16>()
        .map_err(|_| Error::<C>::InvalidMaxSigners)?;

    logger
        .write_all(b"Your identifier (this should be an integer between 1 and 65535):\n")
        .await?;

    let mut identifier_input = String::new();

    input.read_line(&mut identifier_input).await?;

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

pub async fn read_identifier<C: Ciphersuite + 'static>(
    input: &mut (impl BufRead + Send + Sync + Unpin),
) -> Result<Identifier<C>, Box<dyn std::error::Error>> {
    let mut identifier_input = String::new();
    input.read_line(&mut identifier_input).await?;
    let bytes = hex::decode(identifier_input.trim())?;
    let identifier = Identifier::<C>::deserialize(&bytes)?;
    Ok(identifier)
}

pub async fn read_round1_package<C: Ciphersuite + 'static>(
    input: &mut (impl BufRead + Send + Sync + Unpin),
    logger: &mut (dyn Write + Send + Sync + Unpin),
) -> Result<(Identifier<C>, round1::Package<C>), Box<dyn std::error::Error>> {
    logger
        .write_all(b"The sender's identifier (hex string):\n")
        .await?;

    let identifier = read_identifier::<C>(input).await?;

    logger
        .write_all(b"Their JSON-encoded Round 1 Package:\n")
        .await?;

    let mut package_input = String::new();
    input.read_line(&mut package_input).await?;
    let round1_package = serde_json::from_str(&package_input)?;

    Ok((identifier, round1_package))
}

pub async fn read_round2_package<C: Ciphersuite + 'static>(
    input: &mut (impl BufRead + Send + Sync + Unpin),
    logger: &mut (dyn Write + Send + Sync + Unpin),
) -> Result<(Identifier<C>, round2::Package<C>), Box<dyn std::error::Error>> {
    logger
        .write_all(b"The sender's identifier (hex string):\n")
        .await?;

    let identifier = read_identifier::<C>(input).await?;

    logger
        .write_all(b"Their JSON-encoded Round 2 Package:\n")
        .await?;

    let mut package_input = String::new();
    input.read_line(&mut package_input).await?;
    let round2_package = serde_json::from_str(&package_input)?;

    Ok((identifier, round2_package))
}
