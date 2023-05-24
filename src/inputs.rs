use frost_ed25519::Error;
use std::io::BufRead;

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Config {
    pub min_signers: u16,
    pub max_signers: u16,
}

pub struct _SecretConfig {
    pub signers: Config,
    pub secret: Vec<u8>,
}

pub fn validate_inputs(config: &Config) -> Result<(), Error> {
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

    Ok(Config {
        min_signers,
        max_signers,
    })
}
