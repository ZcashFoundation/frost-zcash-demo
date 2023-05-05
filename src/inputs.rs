use std::io;

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Config {
    pub min_signers: u16,
    pub max_signers: u16,
}

pub fn validate_inputs(config: &Config) -> Result<(), frost_ed25519::Error> {
    if config.min_signers < 2 {
        return Err(frost_ed25519::Error::InvalidMinSigners);
    }

    if config.max_signers < 2 {
        return Err(frost_ed25519::Error::InvalidMaxSigners);
    }

    if config.min_signers > config.max_signers {
        return Err(frost_ed25519::Error::InvalidMinSigners);
    }

    Ok(())
}

pub fn request_inputs() -> Config {
    println!("The minimum number of signers: (2 or more)");

    let mut min = String::new();
    io::stdin().read_line(&mut min).expect("Invalid input");

    let min_signers = min.trim().parse::<u16>().expect("Invalid input");

    println!("The maximum number of signers: ");

    let mut max = String::new();
    io::stdin().read_line(&mut max).expect("Invalid input");
    let max_signers = max.trim().parse::<u16>().expect("Invalid input");

    Config {
        min_signers,
        max_signers,
    }
}
