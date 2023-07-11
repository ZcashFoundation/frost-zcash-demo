mod cli;
#[cfg(test)]
mod tests;

use cli::{cli, CliError};
use participant::Logger;

use std::io;

fn main() -> io::Result<()> {
    let mut reader = Box::new(io::stdin().lock());
    let mut logger = ConsoleLogger::default();
    let out = cli(&mut reader, &mut logger);

    if let Err(e) = out {
        if e.cli_error == CliError::Config {
            {
                eprintln!("Error: {}", e.frost_error);
                std::process::exit(exitcode::DATAERR)
            };
        };
        if e.cli_error == CliError::Signing {
            eprintln!("Error: {}", e.frost_error);
            std::process::exit(1)
        };
    }

    Ok(())
}

#[derive(Default)]
pub struct ConsoleLogger;

impl Logger for ConsoleLogger {
    fn log(&mut self, value: String) {
        println!("{}", value);
    }
}
