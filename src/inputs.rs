use std::io;

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Config {
    pub min_signers: u16,
    pub max_signers: u16,
}

pub fn validate_inputs(config: &Config) -> Result<Config, frost_ed25519::Error> {
    if config.min_signers < 2 {
        return Err(frost_ed25519::Error::InvalidMinSigners);
    }

    if config.max_signers < 2 {
        return Err(frost_ed25519::Error::InvalidMaxSigners);
    }

    if config.min_signers > config.max_signers {
        return Err(frost_ed25519::Error::InvalidMinSigners);
    }

    Ok(*config)
}

pub fn request_inputs() -> Config {
    let mut min = "".to_string();

    println!("The minimum number of signers:");
    io::stdin().read_line(&mut min).unwrap(); // TODO: handle errors
    let min_signers = min.trim().parse::<u16>().unwrap();

    let mut max = "".to_string();

    println!("The maximum number of signers:");
    io::stdin().read_line(&mut max).unwrap(); // TODO: handle errors
    let max_signers = max.trim().parse::<u16>().unwrap();

    Config {
        min_signers,
        max_signers,
    }
}
