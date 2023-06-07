mod inputs;
#[cfg(test)]
mod tests;
mod trusted_dealer_keygen;

use std::io;

use output::{print_values, Logger};
use rand::thread_rng;
use trusted_dealer_keygen::split_secret;
mod output;

use crate::inputs::request_inputs;
use crate::trusted_dealer_keygen::trusted_dealer_keygen;

fn main() -> io::Result<()> {
    let mut reader = Box::new(io::stdin().lock());
    let config = request_inputs(&mut reader);
    if let Err(e) = config {
        eprintln!("Error: {}", e);
        std::process::exit(exitcode::DATAERR)
    }

    let config = config.unwrap();

    let mut rng = thread_rng();

    let keygen = if config.secret.is_empty() {
        trusted_dealer_keygen(&config, &mut rng)
    } else {
        split_secret(&config, &mut rng)
    };

    // Print outputs
    if let Err(e) = keygen {
        eprintln!("Error: {}", e);
        std::process::exit(1)
    }

    let (shares, pubkeys) = keygen.unwrap();

    let mut console_logger = ConsoleLogger::default();

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
