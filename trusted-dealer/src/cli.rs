#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use frost::keys::IdentifierList;
use frost::Error;
use rand::thread_rng;
use std::io;

use crate::inputs::request_inputs;
use crate::output::{print_values, Logger};
use crate::trusted_dealer_keygen::{split_secret, trusted_dealer_keygen};

#[derive(PartialEq)]
pub enum CliError {
    Config,
    Keygen,
}

pub struct TrustedDealerError {
    pub frost_error: Error,
    pub cli_error: CliError,
}

// Currently this defaults to the Default value for Identifiers
pub fn cli() -> Result<(), TrustedDealerError> {
    let mut reader = Box::new(io::stdin().lock());
    let config = request_inputs(&mut reader);
    if let Err(e) = config {
        return Err(TrustedDealerError {
            frost_error: e,
            cli_error: CliError::Config,
        });
    }

    let config = config.unwrap();

    let mut rng = thread_rng();

    let keygen = if config.secret.is_empty() {
        trusted_dealer_keygen(&config, IdentifierList::Default, &mut rng)
    } else {
        split_secret(&config, IdentifierList::Default, &mut rng)
    };

    if let Err(e) = keygen {
        return Err(TrustedDealerError {
            frost_error: e,
            cli_error: CliError::Keygen,
        });
    }

    let (shares, pubkeys) = keygen.unwrap();

    let mut console_logger = ConsoleLogger;

    print_values(&shares, &pubkeys, &mut console_logger);

    Ok(())
}

#[derive(Default)]
pub struct ConsoleLogger;

impl Logger for ConsoleLogger {
    fn log(&mut self, value: String) {
        println!("{}", value);
    }
}
