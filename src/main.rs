mod inputs;
#[cfg(test)]
mod tests;
mod trusted_dealer_keygen;

use std::io;

use output::{print_values, Logger};
use rand::thread_rng;
mod output;

use crate::inputs::{request_inputs, validate_inputs};
use crate::trusted_dealer_keygen::trusted_dealer_keygen;

fn main() -> io::Result<()> {
    let mut reader = Box::new(io::stdin().lock());
    let config = request_inputs(&mut reader);
    match config {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(exitcode::DATAERR)
        }
    }

    let config = config.unwrap();

    let mut rng = thread_rng();

    let valid = validate_inputs(&config);
    match valid {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(exitcode::DATAERR)
        }
    }

    // Print outputs
    let out = trusted_dealer_keygen(config, &mut rng);
    match out {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1)
        }
    }

    let (key_packages, pubkeys) = out.unwrap();

    let mut console_logger = ConsoleLogger::default();

    print_values(&key_packages, pubkeys, &mut console_logger);

    Ok(())
}

#[derive(Default)]
pub struct ConsoleLogger;

impl Logger for ConsoleLogger {
    fn log(&mut self, value: String) {
        println!("{}", value);
    }
}
