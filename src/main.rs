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
    let config = request_inputs();
    let mut rng = thread_rng();

    validate_inputs(&config).expect("An error occurred");

    // Print outputs
    let (key_packages, pubkeys) = trusted_dealer_keygen(config, &mut rng);

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
