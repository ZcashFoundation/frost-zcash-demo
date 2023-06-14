mod cli;
mod inputs;
mod output;
mod trusted_dealer_keygen;

#[cfg(test)]
mod tests;

use cli::CliError;
use std::io;

use crate::cli::cli;

fn main() -> io::Result<()> {
    let out = cli();

    if let Err(e) = out {
        if e.cli_error == CliError::Config {
            {
                eprintln!("Error: {}", e.frost_error);
                std::process::exit(exitcode::DATAERR)
            };
        };
        if e.cli_error == CliError::Keygen {
            eprintln!("Error: {}", e.frost_error);
            std::process::exit(1)
        };
    }

    Ok(())
}
