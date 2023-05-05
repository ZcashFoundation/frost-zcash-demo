use std::io::BufRead;

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

pub fn request_inputs(input: &mut impl BufRead) -> Result<Config, frost_ed25519::Error> {
    println!("The minimum number of signers: (2 or more)");

    let mut min = String::new();
    input.read_line(&mut min).unwrap();

    let min_signers = min.trim().parse::<u16>();
    match min_signers {
        Ok(_) => (),
        Err(_) => {
            return Err(frost_ed25519::Error::InvalidMinSigners);
        }
    }

    println!("The maximum number of signers: ");

    let mut max = String::new();
    input.read_line(&mut max).unwrap();
    let max_signers = max.trim().parse::<u16>();
    match max_signers {
        Ok(_) => (),
        Err(_) => {
            return Err(frost_ed25519::Error::InvalidMaxSigners);
        }
    }
    Ok(Config {
        min_signers: min_signers.unwrap(),
        max_signers: max_signers.unwrap(),
    })
}
